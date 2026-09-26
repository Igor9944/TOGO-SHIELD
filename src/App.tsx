import { AlertTriangle, ExternalLink, FileText, Loader2, Send, ShieldCheck, Trash2, UploadCloud } from "lucide-react";
import { ChangeEvent, DragEvent, useRef, useState } from "react";

type ScanResult = { score: number; level: string; threat_type: string; indicators: { description: string }[]; recommendations: string[] };

type FileAnalysis = {
  file: { filename: string; type: string; size: number; sha256: string };
  extracted_content: {
    text: string;
    urls: string[];
    ocr_used: boolean;
    ocr_message?: string | null;
    extraction_method: string;
  };
  analyses: {
    togo_shield?: {
      engine: string;
      score: number;
      risk_level: string;
      threat_type: string;
      reasons: string[];
      recommendations: string[];
      indicators: Array<{ description: string }>;
    } | null;
    urlhaus?: Array<{
      source?: string;
      url: string;
      found: boolean;
      url_status?: string | null;
      threat?: string | null;
      threat_type?: string | null;
      status?: string;
      error?: string | null;
    }>;
  };
};

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp", ".pdf", ".txt"];
const API_URL = (import.meta.env.VITE_API_URL ?? "https://togo-shield.vercel.app").replace(/\/$/, "");
const FILE_API_URL = API_URL ? `${API_URL}/api/analyze/file` : "/api/analyze/file";

const formatBytes = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
};

const normalizeLevel = (level?: string | null) => (level ?? "low").toLowerCase();
const riskBadgeClass = (level?: string | null) => `risk ${normalizeLevel(level)}`;

export default function App() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [content, setContent] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState("");
  const [fileLoading, setFileLoading] = useState(false);
  const [fileResult, setFileResult] = useState<FileAnalysis | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [showMoreExtracted, setShowMoreExtracted] = useState(false);

  const validateSelectedFile = (file: File) => {
    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return "Type de fichier non supporté. Formats acceptés : JPG, JPEG, PNG, WEBP, PDF, TXT.";
    }
    if (file.size > MAX_FILE_SIZE) {
      return "Le fichier est trop volumineux. La taille maximale autorisée est de 10 MB.";
    }
    return "";
  };

  const handleFileSelection = (file?: File) => {
    if (!file) return;
    const validationError = validateSelectedFile(file);
    if (validationError) {
      setSelectedFile(null);
      setFileResult(null);
      setFileError(validationError);
      if (fileInputRef.current) fileInputRef.current.value = "";
      return;
    }
    setFileError("");
    setSelectedFile(file);
    setFileResult(null);
    setShowMoreExtracted(false);
  };

  const onFileInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    handleFileSelection(file);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files?.[0];
    handleFileSelection(file);
  };

  async function scan() {
    if (!content.trim()) return;
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content }),
      });
      if (!response.ok) throw new Error("scan failed");
      setResult(await response.json());
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : "Erreur serveur lors de l'analyse.";
      setFileError(message);
    } finally {
      setLoading(false);
    }
  }

  async function analyzeFile() {
    if (!selectedFile) return;
    const validationError = validateSelectedFile(selectedFile);
    if (validationError) {
      setFileError(validationError);
      return;
    }

    setFileLoading(true);
    setFileError("");
    setFileResult(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await fetch(FILE_API_URL, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        const message = payload?.detail || payload?.error || "Analyse impossible pour le fichier sélectionné.";
        throw new Error(message);
      }

      const data: FileAnalysis = await response.json();
      setFileResult(data);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : "Erreur serveur lors de l'analyse du fichier.";
      setFileError(message);
    } finally {
      setFileLoading(false);
    }
  }

  const clearSelectedFile = () => {
    setSelectedFile(null);
    setFileResult(null);
    setFileError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const extractedText = fileResult?.extracted_content?.text ?? "";
  const extractedUrls = fileResult?.extracted_content?.urls ?? [];
  const showExtractedText = extractedText.length > 700 && !showMoreExtracted ? `${extractedText.slice(0, 700)}...` : extractedText;
  const togoShield = fileResult?.analyses?.togo_shield ?? null;
  const urlhausEntries = fileResult?.analyses?.urlhaus ?? [];

  return (
    <main className="shell">
      <div className="background-logo" aria-hidden="true" />
      <div className="background-overlay" aria-hidden="true" />
      <nav>
        <div className="brand">
          <img src="/brand/togo-shield-logo.jpg" alt="TOGO-SHIELD — Cybersécurité nationale" className="brand-logo" />
        </div>
        <span className="status"><i /> Bot Telegram actif</span>
      </nav>

      <section className="hero">
        <p className="eyebrow">CENTRE DE VIGILANCE NUMERIQUE</p>
        <h1>
          Comprendre une menace<br />
          <em>avant</em> d'y répondre.
        </h1>
        <p className="intro">
          Analysez un message, un lien ou une demande sensible avec le moteur de risque TOGO-SHIELD.
        </p>
      </section>

      <section className="workspace">
        <div className="panel input-panel">
          <div className="panel-heading">
            <span>Nouvelle analyse</span>
            <small>Telegram compatible</small>
          </div>
          <textarea
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Collez ici le message suspect..."
          />
          <button onClick={scan} disabled={loading || !content.trim()}>
            <Send size={16} />
            {loading ? "Analyse..." : "Analyser le message"}
          </button>
          <div className="hint">
            <ExternalLink size={14} /> Les URLs sont inspectées sans être visitées
          </div>
        </div>

        <div className="panel result-panel">
          {result ? (
            <>
              <div className="score-row">
                <div>
                  <small>Score de risque</small>
                  <strong>
                    {result.score}
                    <b>/100</b>
                  </strong>
                </div>
                <span className={`risk ${normalizeLevel(result.level)}`}>{normalizeLevel(result.level)}</span>
              </div>
              <h3>{result.threat_type}</h3>
              <div className="bar">
                <i style={{ width: `${result.score}%` }} />
              </div>
              <p className="label">Indicateurs détectés</p>
              <ul>
                {result.indicators.map((item) => (
                  <li key={item.description}>{item.description}</li>
                ))}
              </ul>
              <p className="label">Recommandations</p>
              <ul className="recommendations">
                {result.recommendations.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </>
          ) : (
            <div className="empty">
              <img src="/brand/togo-shield-logo.jpg" alt="" className="empty-logo" />
              <h3>En attente d'un message</h3>
              <p>Le résultat de votre analyse apparaîtra ici.</p>
            </div>
          )}
        </div>
      </section>

      <section className="panel upload-panel">
        <div className="panel-heading">
          <span>Analyser un fichier</span>
          <small>Upload sécurisé</small>
        </div>

        <div
          className={`dropzone ${isDragging ? "dragging" : ""}`}
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={onDrop}
          role="button"
          tabIndex={0}
          aria-label="Choisir un fichier à analyser"
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              fileInputRef.current?.click();
            }
          }}
        >
          <UploadCloud size={36} />
          <p>Glissez votre fichier ici</p>
          <span>ou cliquez pour choisir</span>
          <small>JPG, JPEG, PNG, WEBP, PDF, TXT • Maximum 10 MB</small>
        </div>

        <input
          ref={fileInputRef}
          type="file"
          accept=".jpg,.jpeg,.png,.webp,.pdf,.txt,image/jpeg,image/png,image/webp,application/pdf,text/plain"
          hidden
          onChange={onFileInputChange}
        />

        {selectedFile && (
          <div className="selected-file">
            <div className="file-data">
              <FileText size={18} />
              <div>
                <strong>{selectedFile.name}</strong>
                <small>{formatBytes(selectedFile.size)}</small>
              </div>
            </div>
            <button className="ghost-button" onClick={clearSelectedFile} type="button">
              <Trash2 size={14} />
              Annuler
            </button>
          </div>
        )}

        {fileError && <div className="error-box">{fileError}</div>}

        <div className="file-actions">
          <button className="ghost-button" type="button" onClick={clearSelectedFile} disabled={!selectedFile}>
            Supprimer
          </button>
          <button type="button" onClick={analyzeFile} disabled={!selectedFile || fileLoading}>
            {fileLoading ? <><Loader2 className="spinner" size={16} /> Analyse en cours...</> : "Analyser"}
          </button>
        </div>

        {fileLoading && (
          <div className="loader-box">
            <Loader2 className="spinner" size={18} />
            <span>🛡️ Analyse de votre fichier...</span>
          </div>
        )}
      </section>

      {fileResult && (
        <section className="file-results">
          <div className="panel file-meta-panel">
            <div className="panel-heading">
              <span>Fichier</span>
              <small>Informations</small>
            </div>
            <ul className="meta-list">
              <li><strong>Nom :</strong> {fileResult.file.filename}</li>
              <li><strong>Type :</strong> {fileResult.file.type || "inconnu"}</li>
              <li><strong>Taille :</strong> {formatBytes(fileResult.file.size)}</li>
              <li><strong>SHA-256 :</strong> {fileResult.file.sha256}</li>
            </ul>
          </div>

          <div className="analysis-grid">
            <div className="panel analysis-panel">
              <h3>🛡️ TOGO-SHIELD</h3>
              {togoShield ? (
                <>
                  <div className="score-row compact">
                    <div>
                      <small>Score</small>
                      <strong>{togoShield.score}<b>/100</b></strong>
                    </div>
                    <span className={riskBadgeClass(togoShield.risk_level)}>{normalizeLevel(togoShield.risk_level)}</span>
                  </div>
                  <p className="label">Niveau</p>
                  <div className="bar">
                    <i style={{ width: `${Math.min(togoShield.score, 100)}%` }} />
                  </div>
                  <p className="label">Raisons</p>
                  <ul>
                    {(togoShield.reasons && togoShield.reasons.length > 0 ? togoShield.reasons : ["Aucun indicateur interne spécifique détecté."]).map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                  {togoShield.recommendations?.length > 0 && (
                    <>
                      <p className="label">Recommandations</p>
                      <ul className="recommendations">
                        {togoShield.recommendations.map((item) => <li key={item}>{item}</li>)}
                      </ul>
                    </>
                  )}
                </>
              ) : (
                <p className="empty-text">Aucune analyse TOGO-SHIELD disponible pour ce fichier.</p>
              )}
            </div>

            <div className="panel analysis-panel">
              <h3>🌐 URLhaus</h3>
              {urlhausEntries.length === 0 ? (
                <p className="empty-text">Aucune URL détectée dans le fichier.</p>
              ) : (
                <>
                  {urlhausEntries.map((entry, index) => (
                    <div key={`${entry.url}-${index}`} className="urlhaus-entry">
                      <p className="url-title">URL analysée : {entry.url}</p>
                      <p><strong>Présente dans URLhaus :</strong> {entry.found ? "Oui" : "Non"}</p>
                      {entry.threat && <p><strong>Threat :</strong> {entry.threat}</p>}
                      {entry.threat_type && <p><strong>Threat type :</strong> {entry.threat_type}</p>}
                      {entry.url_status && <p><strong>URL Status :</strong> {entry.url_status}</p>}
                      {entry.error && <p><strong>Erreur :</strong> {entry.error}</p>}
                      {entry.status === "unavailable" && <p className="empty-text">Service externe temporairement indisponible. L'analyse TOGO-SHIELD reste disponible.</p>}
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>

          <div className="panel extracted-panel">
            <div className="panel-heading">
              <span>📄 Contenu extrait</span>
              <small>{extractedText ? `${extractedText.length} caractères` : "Aucun texte"}</small>
            </div>

            {(fileResult.extracted_content.ocr_used || fileResult.extracted_content.ocr_message) && (
              <div className="info-row">
                <ShieldCheck size={16} />
                <span>{fileResult.extracted_content.ocr_message || "OCR activé."}</span>
              </div>
            )}

            {extractTextForDisplay(extractedText, showMoreExtracted) ? (
              <div className="content-box">
                <pre>{extractTextForDisplay(extractedText, showMoreExtracted)}</pre>
                {extractedText.length > 700 && (
                  <button type="button" className="toggle-button" onClick={() => setShowMoreExtracted(!showMoreExtracted)}>
                    {showMoreExtracted ? "Réduire" : "Afficher plus"}
                  </button>
                )}
              </div>
            ) : (
              <p className="empty-text">Aucun contenu textuel n'a été extrait.</p>
            )}

            {extractedUrls.length > 0 && (
              <div className="url-list-box">
                <p className="label">URLs détectées</p>
                <ul>{extractedUrls.map((url) => <li key={url}>{url}</li>)}</ul>
              </div>
            )}
          </div>
        </section>
      )}

      <footer>
        <span>TOGO-SHIELD / TELEGRAM SECURITY LAYER</span>
        <span>@TOGOShieldBot</span>
      </footer>
    </main>
  );
}

function extractTextForDisplay(text: string, expanded: boolean) {
  if (!text) return "";
  if (text.length <= 700) return text;
  return expanded ? text : `${text.slice(0, 700)}...`;
}
