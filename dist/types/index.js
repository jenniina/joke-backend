"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EUserDeletedFromJoke = exports.EJokeUpdated = exports.EEmailSentToAdministratorPleaseWaitForApproval = exports.EAnErrorOccurredAddingTheJoke = exports.EError = exports.ELanguage = exports.EQuizType = exports.ELanguages = exports.EJokeType = exports.ECategory = void 0;
var ECategory;
(function (ECategory) {
    ECategory["all"] = "All";
    ECategory["misc"] = "Misc";
    ECategory["programming"] = "Programming";
    ECategory["dark"] = "Dark";
    ECategory["pun"] = "Pun";
    ECategory["spooky"] = "Spooky";
    ECategory["christmas"] = "Christmas";
    ECategory["chucknorris"] = "ChuckNorris";
    ECategory["dadjokes"] = "DadJokes";
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
    ELanguages["Suomi"] = "fi";
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
    ELanguage["fi"] = "fi";
})(ELanguage || (exports.ELanguage = ELanguage = {}));
var EError;
(function (EError) {
    EError["en"] = "An error occurred";
    EError["es"] = "Ha ocurrido un error";
    EError["fr"] = "Une erreur est survenue";
    EError["de"] = "Ein Fehler ist aufgetreten";
    EError["pt"] = "Ocorreu um erro";
    EError["cs"] = "Do\u0161lo k chyb\u011B";
    EError["fi"] = "Tapahtui virhe";
})(EError || (exports.EError = EError = {}));
var EAnErrorOccurredAddingTheJoke;
(function (EAnErrorOccurredAddingTheJoke) {
    EAnErrorOccurredAddingTheJoke["en"] = "An error occurred adding the joke";
    EAnErrorOccurredAddingTheJoke["es"] = "Ha ocurrido un error al agregar la broma";
    EAnErrorOccurredAddingTheJoke["fr"] = "Une erreur s'est produite lors de l'ajout de la blague";
    EAnErrorOccurredAddingTheJoke["de"] = "Beim Hinzuf\u00FCgen des Witzes ist ein Fehler aufgetreten";
    EAnErrorOccurredAddingTheJoke["pt"] = "Ocorreu um erro ao adicionar a piada";
    EAnErrorOccurredAddingTheJoke["cs"] = "P\u0159i p\u0159id\u00E1v\u00E1n\u00ED vtipu do\u0161lo k chyb\u011B";
    EAnErrorOccurredAddingTheJoke["fi"] = "Vitsin lis\u00E4\u00E4misess\u00E4 tapahtui virhe";
})(EAnErrorOccurredAddingTheJoke || (exports.EAnErrorOccurredAddingTheJoke = EAnErrorOccurredAddingTheJoke = {}));
// Email sent to administrator, please wait for approval
var EEmailSentToAdministratorPleaseWaitForApproval;
(function (EEmailSentToAdministratorPleaseWaitForApproval) {
    EEmailSentToAdministratorPleaseWaitForApproval["en"] = "Email sent to administrator, please wait for approval";
    EEmailSentToAdministratorPleaseWaitForApproval["es"] = "Correo electr\u00F3nico enviado al administrador, espere la aprobaci\u00F3n";
    EEmailSentToAdministratorPleaseWaitForApproval["fr"] = "Email envoy\u00E9 \u00E0 l administrateur, veuillez attendre l approbation";
    EEmailSentToAdministratorPleaseWaitForApproval["de"] = "E-Mail an Administrator gesendet, bitte warten Sie auf Genehmigung";
    EEmailSentToAdministratorPleaseWaitForApproval["pt"] = "E-mail enviado ao administrador, aguarde a aprova\u00E7\u00E3o";
    EEmailSentToAdministratorPleaseWaitForApproval["cs"] = "E-mail odesl\u00E1n spr\u00E1vci, po\u010Dkejte na schv\u00E1len\u00ED";
    EEmailSentToAdministratorPleaseWaitForApproval["fi"] = "S\u00E4hk\u00F6posti l\u00E4hetetty yll\u00E4pit\u00E4j\u00E4lle, odota hyv\u00E4ksynt\u00E4\u00E4";
})(EEmailSentToAdministratorPleaseWaitForApproval || (exports.EEmailSentToAdministratorPleaseWaitForApproval = EEmailSentToAdministratorPleaseWaitForApproval = {}));
var EJokeUpdated;
(function (EJokeUpdated) {
    EJokeUpdated["en"] = "Joke updated";
    EJokeUpdated["es"] = "Broma actualizada";
    EJokeUpdated["fr"] = "Blague mise \u00E0 jour";
    EJokeUpdated["de"] = "Witz aktualisiert";
    EJokeUpdated["pt"] = "Piada atualizada";
    EJokeUpdated["cs"] = "Vtip aktualizov\u00E1n";
    EJokeUpdated["fi"] = "Vitsi p\u00E4ivitetty";
})(EJokeUpdated || (exports.EJokeUpdated = EJokeUpdated = {}));
// 'User deleted from joke'
var EUserDeletedFromJoke;
(function (EUserDeletedFromJoke) {
    EUserDeletedFromJoke["en"] = "User deleted from joke";
    EUserDeletedFromJoke["es"] = "Usuario eliminado de la broma";
    EUserDeletedFromJoke["fr"] = "Utilisateur supprim\u00E9 de la blague";
    EUserDeletedFromJoke["de"] = "Benutzer aus Witz gel\u00F6scht";
    EUserDeletedFromJoke["pt"] = "Usu\u00E1rio exclu\u00EDdo da piada";
    EUserDeletedFromJoke["cs"] = "U\u017Eivatel smaz\u00E1n z vtipu";
    EUserDeletedFromJoke["fi"] = "K\u00E4ytt\u00E4j\u00E4 poistettu vitsist\u00E4";
})(EUserDeletedFromJoke || (exports.EUserDeletedFromJoke = EUserDeletedFromJoke = {}));
