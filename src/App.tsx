import { Shield, Send, ExternalLink } from "lucide-react";
import { useState } from "react";

type ScanResult = { score: number; level: string; threat_type: string; indicators: { description: string }[]; recommendations: string[] };

const API_URL = import.meta.env.VITE_API_URL ?? "";

export default function App() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);

  async function scan() {
    if (!content.trim()) return;
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content }) });
      if (!response.ok) throw new Error("scan failed");
      setResult(await response.json());
    } finally { setLoading(false); }
  }

  return <main className="shell">
    <nav><div className="brand"><Shield size={22} /> TOGO-SHIELD</div><span className="status"><i /> Bot Telegram actif</span></nav>
    <section className="hero"><p className="eyebrow">CENTRE DE VIGILANCE NUMERIQUE</p><h1>Comprendre une menace<br /><em>avant</em> d'y répondre.</h1><p className="intro">Analysez un message, un lien ou une demande sensible avec le moteur de risque TOGO-SHIELD.</p></section>
    <section className="workspace"><div className="panel input-panel"><div className="panel-heading"><span>Nouvelle analyse</span><small>Telegram compatible</small></div><textarea value={content} onChange={(event) => setContent(event.target.value)} placeholder="Collez ici le message suspect..." /><button onClick={scan} disabled={loading || !content.trim()}><Send size={16} /> {loading ? "Analyse..." : "Analyser le message"}</button><div className="hint"><ExternalLink size={14} /> Les URLs sont inspectées sans être visitées</div></div>
      <div className="panel result-panel">{result ? <><div className="score-row"><div><small>Score de risque</small><strong>{result.score}<b>/100</b></strong></div><span className={`risk ${result.level}`}>{result.level}</span></div><h3>{result.threat_type}</h3><div className="bar"><i style={{ width: `${result.score}%` }} /></div><p className="label">Indicateurs détectés</p><ul>{result.indicators.map((item) => <li key={item.description}>{item.description}</li>)}</ul><p className="label">Recommandations</p><ul className="recommendations">{result.recommendations.map((item) => <li key={item}>{item}</li>)}</ul></> : <div className="empty"><Shield size={42} /><h3>En attente d'un message</h3><p>Le résultat de votre analyse apparaîtra ici.</p></div>}</div></section>
    <footer><span>TOGO-SHIELD / TELEGRAM SECURITY LAYER</span><span>@TOGOShieldBot</span></footer>
  </main>;
}
