const { createWorker } = require("tesseract.js");

const MAX_BYTES = 10 * 1024 * 1024;
const WORKER_PATH = require.resolve("tesseract.js/src/worker-script/node/index.js");

function readBody(req) {
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  if (typeof req.body === "string") return Promise.resolve(Buffer.from(req.body, "binary"));

  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on("data", (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buffer.length;
      if (total > MAX_BYTES) {
        reject(new Error("PAYLOAD_TOO_LARGE"));
        req.destroy();
        return;
      }
      chunks.push(buffer);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ detail: "Method Not Allowed" });
  }

  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (!contentType.startsWith("image/") && contentType !== "application/octet-stream") {
    return res.status(415).json({ detail: "Unsupported image type" });
  }

  let image;
  try {
    image = await readBody(req);
  } catch (error) {
    if (error?.message === "PAYLOAD_TOO_LARGE") {
      return res.status(413).json({ detail: "Image is too large" });
    }
    return res.status(400).json({ detail: "Invalid request body" });
  }

  if (!image.length) {
    return res.status(400).json({ detail: "Empty image" });
  }

  let worker;
  try {
    worker = await createWorker(["fra", "eng"], 1, {
      workerPath: WORKER_PATH,
    });
    const result = await worker.recognize(image);
    const text = String(result?.data?.text || "").trim();
    return res.status(200).json({
      text,
      ocr_used: Boolean(text),
      engine: "tesseract.js",
      languages: ["fra", "eng"],
    });
  } catch (error) {
    console.error("OCR failed:", error);
    return res.status(500).json({
      detail: "OCR processing failed",
      error_type: error?.name || "Error",
    });
  } finally {
    if (worker) {
      try {
        await worker.terminate();
      } catch (_) {}
    }
  }
};
