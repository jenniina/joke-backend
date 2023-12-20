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
exports.sendVerificationLink = exports.sendEmailSelect = exports.sendEmailForm = void 0;
const users_1 = require("../users");
const { validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const nodemailer = require('nodemailer');
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
            ${process.env.SITE_URL}/verify/${token}
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
