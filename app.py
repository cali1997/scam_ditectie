from pathlib import Path
import re

from flask import Flask, jsonify, request, send_from_directory
import yaml


BASE_DIR = Path(__file__).parent
app = Flask(__name__)

with (BASE_DIR / "rules.yaml").open(encoding="utf-8") as rule_file:
    RULES = yaml.safe_load(rule_file)["rules"]


MESSAGES = {
    "nl": {
        "high": ("Waarschijnlijk verdacht", "Open geen links en deel geen gegevens.", "Gebruik geen link in het bericht. Controleer de afzender via een bekend kanaal en neem geen gevoelige gegevens op."),
        "medium": ("Controleer dit goed", "Wees extra kritisch op de afzender.", "Er zijn aanwijzingen voor phishing. Controleer de afzender en twijfel niet aan een onverwachte vraag om gegevens."),
        "low": ("Weinig signalen gevonden", "Er zijn geen sterke phishing-signalen herkend.", "Het bericht lijkt redelijk veilig, maar blijf alert bij onbekende afzenders of onverwachte verzoeken."),
    },
    "en": {
        "high": ("Probably suspicious", "Do not open links or share personal information.", "Do not click any link in the message. Verify the sender through a trusted channel and never share sensitive information."),
        "medium": ("Check this carefully", "Be extra critical of the sender.", "There are signs of phishing. Verify the sender and be cautious with unexpected requests for information."),
        "low": ("Few signals found", "No strong phishing signals were found.", "The message seems relatively safe, but stay alert for unknown senders or unexpected requests."),
    },
    "fr": {
        "high": ("Probablement suspect", "N'ouvrez pas de liens et ne partagez pas vos donnees.", "N'utilisez pas le lien dans le message. Verifiez l'expediteur via un canal fiable et ne partagez aucune information sensible."),
        "medium": ("Verifiez attentivement", "Soyez tres critique envers l'expediteur.", "Il y a des signes de phishing. Verifiez l'expediteur et soyez prudent face a une demande inattendue de donnees."),
        "low": ("Peu de signaux trouves", "Aucun signal fort de phishing n'a ete trouve.", "Le message semble relativement securise, mais restez vigilant face a un expediteur inconnu."),
    },
    "ar": {
        "high": ("رسالة مشبوهة على الأرجح", "لا تفتح الروابط ولا تشارك بياناتك.", "لا تنقر على أي رابط في الرسالة. التحقق من المرسل عبر قناة موثوقة وعدم مشاركة أي معلومات حساسة."),
        "medium": ("تحقق من هذه الرسالة جيداً", "كن حذراً من المرسل.", "هناك مؤشرات على التصيد الاحتيالي. تحقق من المرسل وكن حذراً من أي طلب غير متوقع للمعلومات."),
        "low": ("تم العثور على مؤشرات قليلة", "لم يتم العثور على مؤشرات قوية للتصيد الاحتيالي.", "الرسالة تبدو آمنة نسبيًا، لكن ابقَ حذراً تجاه المرسلين غير المعروفين أو الطلبات غير المتوقعة."),
    },
}


def analyse_message(text: str, language: str) -> dict:
    matches = [rule for rule in RULES if re.search(rule["pattern"], text, re.IGNORECASE)]
    base_score = sum(rule["points"] for rule in matches)
    combined_bonus = max(0, (len(matches) - 1) * 8)
    score = min(100, base_score + combined_bonus)
    messages = MESSAGES[language]

    if score >= 50:
        result_title, result_subtitle, recommendation = messages["high"]
        risk_level = "high"
        risk_label = {"nl": "Waarschijnlijk verdacht", "en": "High risk", "fr": "Probablement suspect", "ar": "خطير"}[language]
    elif score >= 20:
        result_title, result_subtitle, recommendation = messages["medium"]
        risk_level = "medium"
        risk_label = {"nl": "Let op", "en": "Medium risk", "fr": "Attention", "ar": "تمت مراجعته"}[language]
    else:
        result_title, result_subtitle, recommendation = messages["low"]
        risk_level = "low"
        risk_label = {"nl": "Laag risico", "en": "Low risk", "fr": "Faible risque", "ar": "مخاطر منخفضة"}[language]

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "title": result_title,
        "subtitle": result_subtitle,
        "recommendation": recommendation,
        "findings": [
            {
                "title": rule["translations"][language]["title"],
                "detail": rule["translations"][language]["detail"],
            }
            for rule in matches
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