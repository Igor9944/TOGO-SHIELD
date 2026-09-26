import { createWorker } from "tesseract.js";

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/webp"]);

type NodeRequest = AsyncIterable<Uint8Array> & {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
};

type NodeResponse = {
  statusCode: number;
  setHeader(name: string, value: string | number): void;
  end(body?: string): void;
};

export const config = {
  api: {
    bodyParser: false,
  },
  maxDuration: 60,
};

async function readRequestBody(req: NodeRequest): Promise<Buffer> {
  if (Buffer.isBuffer(req.body)) return req.body;
  if (req.body instanceof Uint8Array) return Buffer.from(req.body);

  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of req) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_IMAGE_BYTES) {
      throw new Error("FILE_TOO_LARGE");
    }
    chunks.push(buffer);
  }

  return Buffer.concat(chunks);
}

export default async function handler(req: NodeRequest, res: NodeResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "POST, OPTIONS");
    return res.end(JSON.stringify({ detail: "Méthode non autorisée" }));
  }

  const contentTypeHeader = req.headers["content-type"];
  const contentType = Array.isArray(contentTypeHeader)
    ? contentTypeHeader[0]
    : contentTypeHeader || "";

  if (!ALLOWED_TYPES.has(contentType.split(";")[0].trim().toLowerCase())) {
    res.statusCode = 415;
    return res.end(JSON.stringify({ detail: "Type d'image non supporté" }));
  }

  try {
    const image = await readRequestBody(req);

    if (!image.length) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ detail: "Image vide" }));
    }

    if (image.length > MAX_IMAGE_BYTES) {
      res.statusCode = 413;
      return res.end(JSON.stringify({ detail: "Image trop volumineuse (10 MB maximum)" }));
    }

    const worker = await createWorker(["eng", "fra"]);

    try {
      const {
        data: { text },
      } = await worker.recognize(image);

      const normalizedText = text.replace(/\r\n/g, "\n").trim();

      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      return res.end(
        JSON.stringify({
          text: normalizedText,
          ocr_used: true,
          extraction_method: "tesseract_js",
        }),
      );
    } finally {
      await worker.terminate();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "OCR error";

    if (message === "FILE_TOO_LARGE") {
      res.statusCode = 413;
      return res.end(JSON.stringify({ detail: "Image trop volumineuse (10 MB maximum)" }));
    }

    console.error("OCR error:", error);
    res.statusCode = 500;
    return res.end(JSON.stringify({ detail: "OCR indisponible" }));
  }
}
