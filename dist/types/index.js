"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ELanguages = exports.EJokeType = exports.ECategory = void 0;
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
