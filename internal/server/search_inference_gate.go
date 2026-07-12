package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	searchGlobalInputsPerSecond  = 100
	searchGlobalInputBurst       = 256
	searchGlobalConcurrentCalls  = 16
	searchUserInputsPerSecond    = 10
	searchUserInputBurst         = 32
	searchUserConcurrentCalls    = 2
	searchLimiterIdleTTL         = 10 * time.Minute
	searchLimiterMaxTrackedUsers = 10_000
	searchLimiterRetryInterval   = 100 * time.Millisecond
)

type searchInferenceLimits struct {
	globalRate       rate.Limit
	globalBurst      int
	globalConcurrent int
	userRate         rate.Limit
	userBurst        int
	userConcurrent   int
}

var defaultSearchInferenceLimits = searchInferenceLimits{
	globalRate:       searchGlobalInputsPerSecond,
	globalBurst:      searchGlobalInputBurst,
	globalConcurrent: searchGlobalConcurrentCalls,
	userRate:         searchUserInputsPerSecond,
	userBurst:        searchUserInputBurst,
	userConcurrent:   searchUserConcurrentCalls,
}

type searchUserInferenceLimit struct {
	foreground *rate.Limiter
	background *rate.Limiter
	slots      chan struct{}
	lastUsed   time.Time
	active     int
}

type searchInferenceGate struct {
	mu          sync.Mutex
	rateMu      sync.Mutex
	limits      searchInferenceLimits
	global      *rate.Limiter
	globalSlots chan struct{}
	users       map[string]*searchUserInferenceLimit
}

func newSearchInferenceGate(limits searchInferenceLimits) *searchInferenceGate {
	return &searchInferenceGate{
		limits:      limits,
		global:      rate.NewLimiter(limits.globalRate, limits.globalBurst),
		globalSlots: make(chan struct{}, limits.globalConcurrent),
		users:       make(map[string]*searchUserInferenceLimit),
	}
}

func (g *searchInferenceGate) beginUser(userID string, now time.Time) *searchUserInferenceLimit {
	g.mu.Lock()
	defer g.mu.Unlock()
	if user, ok := g.users[userID]; ok {
		user.lastUsed = now
		user.active++
		return user
	}
	if len(g.users) >= searchLimiterMaxTrackedUsers {
		var oldestID string
		var oldest time.Time
		for id, user := range g.users {
			if user.active != 0 {
				continue
			}
			if now.Sub(user.lastUsed) >= searchLimiterIdleTTL {
				delete(g.users, id)
				continue
			}
			if oldestID == "" || user.lastUsed.Before(oldest) {
				oldestID, oldest = id, user.lastUsed
			}
		}
		if len(g.users) >= searchLimiterMaxTrackedUsers && oldestID != "" {
			delete(g.users, oldestID)
		}
		if len(g.users) >= searchLimiterMaxTrackedUsers {
			return nil
		}
	}
	user := &searchUserInferenceLimit{
		foreground: rate.NewLimiter(g.limits.userRate, g.limits.userBurst),
		background: rate.NewLimiter(g.limits.userRate, g.limits.userBurst),
		slots:      make(chan struct{}, g.limits.userConcurrent),
		lastUsed:   now,
		active:     1,
	}
	g.users[userID] = user
	return user
}

func (g *searchInferenceGate) acquire(ctx context.Context, userID string, inputs int, wait bool) (func(), error) {
	if inputs <= 0 {
		return func() {}, nil
	}
	user := g.beginUser(userID, time.Now())
	if user == nil {
		return nil, searchInferenceLimited()
	}
	finish := func() {
		g.mu.Lock()
		user.active--
		user.lastUsed = time.Now()
		g.mu.Unlock()
	}
	limiter := user.foreground
	if wait {
		limiter = user.background
		if !waitForSearchInferenceRate(ctx, g, limiter, inputs) {
			finish()
			return nil, searchInferenceLimited()
		}
	}
	if !takeSearchInferenceSlot(ctx, user.slots, wait) {
		finish()
		return nil, searchInferenceLimited()
	}
	if !takeSearchInferenceSlot(ctx, g.globalSlots, wait) {
		<-user.slots
		finish()
		return nil, searchInferenceLimited()
	}
	if !wait && !g.reserveRate(limiter, inputs) {
		<-g.globalSlots
		<-user.slots
		finish()
		return nil, searchInferenceLimited()
	}
	return func() {
		<-g.globalSlots
		<-user.slots
		finish()
	}, nil
}

func waitForSearchInferenceRate(ctx context.Context, gate *searchInferenceGate, user *rate.Limiter, inputs int) bool {
	if inputs > user.Burst() || inputs > gate.global.Burst() {
		return false
	}
	ticker := time.NewTicker(searchLimiterRetryInterval)
	defer ticker.Stop()
	for {
		if gate.reserveRate(user, inputs) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (g *searchInferenceGate) reserveRate(user *rate.Limiter, inputs int) bool {
	now := time.Now()
	g.rateMu.Lock()
	defer g.rateMu.Unlock()

	userReservation := user.ReserveN(now, inputs)
	if !userReservation.OK() || userReservation.DelayFrom(now) > 0 {
		if userReservation.OK() {
			userReservation.CancelAt(now)
		}
		return false
	}
	globalReservation := g.global.ReserveN(now, inputs)
	if !globalReservation.OK() || globalReservation.DelayFrom(now) > 0 {
		if globalReservation.OK() {
			globalReservation.CancelAt(now)
		}
		userReservation.CancelAt(now)
		return false
	}
	return true
}

func takeSearchInferenceSlot(ctx context.Context, slots chan struct{}, wait bool) bool {
	if wait {
		select {
		case slots <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func searchInferenceLimited() *AppError {
	return &AppError{
		Status:  http.StatusTooManyRequests,
		Code:    CodeRateLimited,
		Message: "search inference limit exceeded",
	}
}

func embedWithSearchInferenceGate(ctx context.Context, deps Deps, userID string, inputs []string, wait bool) ([][]float32, error) {
	if deps.searchGate == nil {
		return deps.Embedder.Embed(ctx, inputs)
	}
	release, err := deps.searchGate.acquire(ctx, userID, len(inputs), wait)
	if err != nil {
		return nil, err
	}
	defer release()
	return deps.Embedder.Embed(ctx, inputs)
}
