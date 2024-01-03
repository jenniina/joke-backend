"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendVerificationLink = exports.sendEmailSelect = exports.sendEmailForm = exports.sendMail = exports.EErrorSendingMail = exports.EEmailSent = void 0;
const users_1 = require("../users");
var EEmailSent;
(function (EEmailSent) {
    EEmailSent["en"] = "Email sent";
    EEmailSent["es"] = "Correo electr\u00F3nico enviado";
    EEmailSent["fr"] = "Email envoy\u00E9";
    EEmailSent["de"] = "E-Mail gesendet";
    EEmailSent["pt"] = "Email enviado";
    EEmailSent["cs"] = "E-mail odesl\u00E1n";
    EEmailSent["fi"] = "S\u00E4hk\u00F6posti l\u00E4hetetty";
})(EEmailSent || (exports.EEmailSent = EEmailSent = {}));
var EErrorSendingMail;
(function (EErrorSendingMail) {
    EErrorSendingMail["en"] = "Error sending email";
    EErrorSendingMail["es"] = "Error al enviar el correo electr\u00F3nico";
    EErrorSendingMail["fr"] = "Erreur lors de l'envoi du courriel";
    EErrorSendingMail["de"] = "Fehler beim Senden der E-Mail";
    EErrorSendingMail["pt"] = "Erro ao enviar e-mail";
    EErrorSendingMail["cs"] = "Chyba p\u0159i odes\u00EDl\u00E1n\u00ED e-mailu";
    EErrorSendingMail["fi"] = "Virhe s\u00E4hk\u00F6postin l\u00E4hetyksess\u00E4";
})(EErrorSendingMail || (exports.EErrorSendingMail = EErrorSendingMail = {}));
const { validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
        user: process.env.NODEMAILER_USER,
        pass: process.env.NODEMAILER_PASSWORD,
    },
});
const sendMail = (subject, message, username, language, link) => {
    return new Promise((resolve, reject) => {
        transporter.sendMail({
            from: process.env.NODEMAILER_USER,
            to: username,
            subject: subject,
            text: message + ': ' + link || link,
        }, (error, info) => {
            if (error) {
                console.log(error);
                reject(error);
                return error;
            }
            else {
                console.log('Email sent: ' + info.response);
                resolve(info.response);
                return info.response;
            }
        });
    });
};
exports.sendMail = sendMail;
const sendEmailForm = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors);
        return res.status(400).json({ errors: errors.array() });
    }
    const sanitizedMessage = sanitizeHtml(req.body.message);
    const sanitizedEncouragement = sanitizeHtml(req.body.encouragement);
    const sanitizedClarification = sanitizeHtml(req.body.clarification);
    const { firstName, lastName, email } = req.body;
    let transporter = nodemailer.createTransport({
        host: process.env.NODEMAILER_HOST,
        port: process.env.NODEMAILER_PORT,
        auth: {
            user: process.env.NODEMAILER_USER,
            pass: process.env.NODEMAILER_PASSWORD,
        },
    });
    let mailOptions = {
        from: process.env.NODEMAILER_USER,
        to: process.env.NODEMAILER_USER,
        subject: `Message from ${firstName} ${lastName}`,
        text: `
    Subject: ${req.body.select}
    Message: ${sanitizedMessage}
    Encouragement: ${sanitizedEncouragement}
    Color: ${req.body.color}
    Preference: ${req.body.dark}${req.body.light}
    Select Multi: ${req.body.selectmulti}
    Clarification: ${sanitizedClarification}
    From: ${email}
  `,
    };
    try {
        yield transporter.sendMail(mailOptions);
        res.status(200).send('Email sent');
    }
    catch (error) {
        console.log(error);
        res.status(500).send('Error sending email');
    }
});
exports.sendEmailForm = sendEmailForm;
const sendEmailSelect = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    console.log(req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors);
        return res.status(400).json({ errors: errors.array() });
    }
    const sanitizedMessage = sanitizeHtml(req.body.clarification);
    const sanitizedEmail = sanitizeHtml(req.body.email);
    const { favoriteHero, issues } = req.body;
    let transporter = nodemailer.createTransport({
        host: 'smtp-relay.brevo.com',
        port: 587,
        auth: {
            user: process.env.NODEMAILER_USER,
            pass: process.env.NODEMAILER_PASSWORD,
        },
    });
    let mailOptions = {
        from: process.env.NODEMAILER_USER,
        to: process.env.NODEMAILER_USER,
        subject: `Message from React Custom Select Page`,
        text: `
        Issues: ${issues}
        Favorite Hero Section: ${favoriteHero}
        Clarification: ${sanitizedMessage} 
        Email: ${sanitizedEmail}
    `,
    };
    try {
        yield transporter.sendMail(mailOptions);
        res.status(200).send('Email sent');
    }
    catch (error) {
        console.log(error);
        res.status(500).send('Error sending email');
    }
});
exports.sendEmailSelect = sendEmailSelect;
const sendVerificationLink = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log(errors);
        return res.status(400).json({ errors: errors.array() });
    }
    const { email } = req.body;
    const token = (0, users_1.generateToken)(email);
    let transporter = nodemailer.createTransport({
        host: 'smtp-relay.brevo.com',
        port: 587,
        auth: {
            user: process.env.NODEMAILER_USER,
            pass: process.env.NODEMAILER_PASSWORD,
        },
    });
    let mailOptions = {
        from: process.env.NODEMAILER_USER,
        to: email,
        subject: `Verify your email address for jenniina.fi`,
        text: `
            Click the link below to verify your email address.
            ${process.env.BASE_URI}/verify/${token}
        `,
    };
    try {
        yield transporter.sendMail(mailOptions);
        res.status(200).send('Email sent');
    }
    catch (error) {
        console.log(error);
        res.status(500).send('Error sending email');
    }
});
exports.sendVerificationLink = sendVerificationLink;
