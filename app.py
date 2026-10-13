from pathlib import Path
import re

from flask import Flask, jsonify, request, send_from_directory
import yaml


BASE_DIR = Path(__file__).parent
app = Flask(__name__)

with (BASE_DIR / "rules.yaml").open(encoding="utf-8") as rule_file:
    RULES = yaml.safe_load(rule_file)["rules"]


MESSAGES = {
    "nl": {"high": ("Waarschijnlijk verdacht", "Open geen links en deel geen gegevens."), "medium": ("Controleer dit goed", "Wees extra kritisch op de afzender."), "low": ("Weinig signalen gevonden", "Er zijn geen sterke phishing-signalen herkend.")},
    "en": {"high": ("Probably suspicious", "Do not open links or share personal information."), "medium": ("Check this carefully", "Be extra critical of the sender."), "low": ("Few signals found", "No strong phishing signals were found.")},
    "fr": {"high": ("Probablement suspect", "N'ouvrez pas de liens et ne partagez pas vos donnees."), "medium": ("Verifiez attentivement", "Soyez tres critique envers l'expediteur."), "low": ("Peu de signaux trouves", "Aucun signal fort de phishing n'a ete trouve.")},
    "ar": {"high": ("رسالة مشبوهة على الأرجح", "لا تفتح الروابط ولا تشارك بياناتك."), "medium": ("تحقق من هذه الرسالة جيداً", "كن حذراً من المرسل."), "low": ("تم العثور على مؤشرات قليلة", "لم يتم العثور على مؤشرات قوية للتصيد الاحتيالي.")},
}


def analyse_message(text: str, language: str) -> dict:
    matches = [rule for rule in RULES if re.search(rule["pattern"], text, re.IGNORECASE)]
    score = min(100, sum(rule["points"] for rule in matches))
    messages = MESSAGES[language]

    if score >= 50:
        result_title, result_subtitle = messages["high"]
    elif score >= 20:
        result_title, result_subtitle = messages["medium"]
    else:
        result_title, result_subtitle = messages["low"]

    return {
        "score": score,
        "title": result_title,
        "subtitle": result_subtitle,
        "findings": [
            {"title": rule["translations"][language]["title"], "detail": rule["translations"][language]["detail"]} for rule in matches
        ],
    }


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.post("/api/analyse")
def analyse():
    payload = request.get_json(silent=True) or {}
    text = payload.get("message", "")
    language = payload.get("language", "nl")

    if not isinstance(text, str):
        return jsonify({"error": "Het bericht moet tekst zijn."}), 400
    if language not in MESSAGES:
        return jsonify({"error": "Unsupported language."}), 400

    return jsonify(analyse_message(text.strip(), language))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)