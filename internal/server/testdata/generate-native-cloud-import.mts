import { Blob, File } from "node:buffer";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const webappDir = process.env.WEBAPP_DIR;
const outputPath = process.argv[2];
if (!webappDir || !outputPath)
  throw new Error("usage: WEBAPP_DIR=<checkout> vite-node <script> <output>");

Object.defineProperties(globalThis, {
  Blob: { value: Blob },
  File: { value: File },
  navigator: { value: {} },
});

const fixedTime = new Date("2026-08-20T12:00:00.000Z").valueOf();
const NativeDate = Date;
class FixedDate extends NativeDate {
  constructor(...args: ConstructorParameters<typeof Date>) {
    super(...(args.length ? args : [fixedTime]));
  }

  static now() {
    return fixedTime;
  }
}
globalThis.Date = FixedDate as DateConstructor;

const format = await import(
  pathToFileURL(path.join(webappDir, "src/services/native-backup/format.ts"))
    .href
);
const restore = await import(
  pathToFileURL(path.join(webappDir, "src/services/native-backup/restore.ts"))
    .href
);
const png = new Uint8Array([
  0x89,
  0x50,
  0x4e,
  0x47,
  0x0d,
  0x0a,
  0x1a,
  0x0a,
  ...new Array(64).fill(0x42),
]);
const timestamp = new NativeDate(fixedTime).toISOString();
const formatted = format.formatNativeBackupV1({
  backupId: "123e4567-e89b-42d3-a456-426614174000",
  createdAt: timestamp,
  projects: [
    {
      id: "project-1",
      name: "Research",
      description: "Description",
      systemInstructions: "Be exact",
      color: "#123456",
      memory: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    },
  ],
  projectDocuments: [
    {
      id: "document-1",
      projectId: "project-1",
      filename: "paper.pdf",
      contentType: "application/pdf",
      sizeBytes: 9000,
      extractedText: "Extracted text",
      createdAt: timestamp,
      updatedAt: timestamp,
    },
  ],
  cloudChats: [
    {
      id: "cloud-1",
      title: "Cloud chat",
      titleState: "manual",
      messages: [
        {
          role: "user",
          content: "hello",
          timestamp,
          attachments: [
            { id: "cloud-image", type: "image", imageId: "cloud-image" },
          ],
        },
      ],
      createdAt: timestamp,
      updatedAt: timestamp,
      projectId: "project-1",
      model: "gpt-oss-120b",
    },
  ],
  localChats: [
    {
      id: "local-1",
      title: "Local chat",
      messages: [
        {
          role: "user",
          content: "local",
          timestamp,
          attachments: [
            { id: "local-image", type: "image", imageId: "local-image" },
          ],
        },
      ],
      createdAt: timestamp,
      updatedAt: timestamp,
    },
  ],
  relationships: {
    projectChats: [{ projectId: "project-1", chatId: "cloud-1" }],
    projectDocuments: [{ projectId: "project-1", documentId: "document-1" }],
    chatImages: [
      { chatId: "cloud-1", imageId: "cloud-image" },
      { chatId: "local-1", imageId: "local-image" },
    ],
  },
  images: [
    {
      metadata: {
        id: "cloud-image",
        chatId: "cloud-1",
        messageIndex: 0,
        attachmentId: "cloud-image",
        fileName: "photo.png",
        mimeType: "image/png",
      },
      bytes: png,
    },
    {
      metadata: {
        id: "local-image",
        chatId: "local-1",
        messageIndex: 0,
        attachmentId: "local-image",
        fileName: "local.png",
        mimeType: "image/png",
      },
      bytes: png,
    },
  ],
});

const values = [
  { path: "manifest.json", bytes: formatted.manifestBytes },
  ...formatted.files,
];
const sourceFile = new File([], "native-backup.zip", {
  type: "application/zip",
});
const packaged = await restore.validateAndPackageNativeBackup(sourceFile, {
  dependencies: {
    openArchive: async () => ({
      entries: values.map(({ path, bytes }) => ({
        path,
        directory: false,
        encrypted: false,
        compressedSize: bytes.length,
        uncompressedSize: bytes.length,
        read: async () => ({ bytes, release: () => undefined }),
      })),
      close: async () => undefined,
    }),
  },
});
if (packaged.cloud?.upload.kind !== "blob")
  throw new Error("expected in-memory cloud package");

await writeFile(
  outputPath,
  new Uint8Array(await packaged.cloud.upload.blob.arrayBuffer()),
);
