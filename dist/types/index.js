"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EAnErrorOccurredAddingTheJoke = exports.EError = exports.ELanguage = exports.EQuizType = exports.ELanguages = exports.EJokeType = exports.ECategory = void 0;
var ECategory;
(function (ECategory) {
    ECategory["all"] = "All";
    ECategory["misc"] = "Misc";
    ECategory["programming"] = "Programming";
    ECategory["dark"] = "Dark";
    ECategory["pun"] = "Pun";
    ECategory["spooky"] = "Spooky";
    ECategory["christmas"] = "Christmas";
})(ECategory || (exports.ECategory = ECategory = {}));
var EJokeType;
(function (EJokeType) {
    EJokeType["single"] = "single";
    EJokeType["twopart"] = "twopart";
})(EJokeType || (exports.EJokeType = EJokeType = {}));
var ELanguages;
(function (ELanguages) {
    ELanguages["English"] = "en";
    ELanguages["Spanish"] = "es";
    ELanguages["French"] = "fr";
    ELanguages["German"] = "de";
    ELanguages["Portuguese"] = "pt";
    ELanguages["Czech"] = "cs";
})(ELanguages || (exports.ELanguages = ELanguages = {}));
var EQuizType;
(function (EQuizType) {
    EQuizType["easy"] = "easy";
    EQuizType["medium"] = "medium";
    EQuizType["hard"] = "hard";
})(EQuizType || (exports.EQuizType = EQuizType = {}));
var ELanguage;
(function (ELanguage) {
    ELanguage["en"] = "en";
    ELanguage["es"] = "es";
    ELanguage["fr"] = "fr";
    ELanguage["de"] = "de";
    ELanguage["pt"] = "pt";
    ELanguage["cs"] = "cs";
})(ELanguage || (exports.ELanguage = ELanguage = {}));
var EError;
(function (EError) {
    EError["en"] = "An error occurred";
    EError["es"] = "Ha ocurrido un error";
    EError["fr"] = "Une erreur est survenue";
    EError["de"] = "Ein Fehler ist aufgetreten";
    EError["pt"] = "Ocorreu um erro";
    EError["cs"] = "Do\u0161lo k chyb\u011B";
})(EError || (exports.EError = EError = {}));
var EAnErrorOccurredAddingTheJoke;
(function (EAnErrorOccurredAddingTheJoke) {
    EAnErrorOccurredAddingTheJoke["en"] = "An error occurred adding the joke";
    EAnErrorOccurredAddingTheJoke["es"] = "Ha ocurrido un error al agregar la broma";
    EAnErrorOccurredAddingTheJoke["fr"] = "Une erreur s'est produite lors de l'ajout de la blague";
    EAnErrorOccurredAddingTheJoke["de"] = "Beim Hinzuf\u00FCgen des Witzes ist ein Fehler aufgetreten";
    EAnErrorOccurredAddingTheJoke["pt"] = "Ocorreu um erro ao adicionar a piada";
    EAnErrorOccurredAddingTheJoke["cs"] = "P\u0159i p\u0159id\u00E1v\u00E1n\u00ED vtipu do\u0161lo k chyb\u011B";
})(EAnErrorOccurredAddingTheJoke || (exports.EAnErrorOccurredAddingTheJoke = EAnErrorOccurredAddingTheJoke = {}));
