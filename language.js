function translate(key, lang) {
    return translations[lang][key] || key;
}