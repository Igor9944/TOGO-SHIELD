const { createWorker } = require("tesseract.js");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") return res.status(405).json({ detail: "Method Not Allowed" });

  const sampleUrl = "https://tesseract.projectnaptha.com/img/eng_bw.png";
  let worker;
  try {
    const response = await fetch(sampleUrl);
    if (!response.ok) throw new Error("sample fetch failed");
    const image = Buffer.from(await response.arrayBuffer());
    worker = await createWorker("eng", 1, {
      workerPath: "https://cdn.jsdelivr.net/npm/tesseract.js@7.0.0/dist/worker.min.js",
      corePath: "https://cdn.jsdelivr.net/npm/tesseract.js-core@7.0.0",
    });
    const result = await worker.recognize(image);
    return res.status(200).json({
      ok: true,
      engine: "tesseract.js",
      text: String(result?.data?.text || "").trim(),
    });
  } catch (error) {
    console.error("OCR test failed:", error);
    return res.status(500).json({ ok: false, error_type: error?.name || "Error" });
  } finally {
    if (worker) await worker.terminate().catch(() => {});
  }
};
