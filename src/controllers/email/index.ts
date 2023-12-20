import { Request, Response } from 'express'
import { generateToken } from '../users'
export type FormData = {
  firstName: string
  lastName: string
  encouragement: string
  color: string
  dark: string
  light: string
  email: string
  message: string
  gdpr: string
  select: string
  selectmulti: string
  clarification: string
}
export type SelectData = {
  issues: string
  favoriteHero: string
  clarification: string
}

const { validationResult } = require('express-validator')
const sanitizeHtml = require('sanitize-html')
const nodemailer = require('nodemailer')

export const sendEmailForm = async (req: Request, res: Response) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    console.log(errors)
    return res.status(400).json({ errors: errors.array() })
  }

  const sanitizedMessage = sanitizeHtml(req.body.message)
  const sanitizedEncouragement = sanitizeHtml(req.body.encouragement)
  const sanitizedClarification = sanitizeHtml(req.body.clarification)
  const { firstName, lastName, email } = req.body

  let transporter = nodemailer.createTransport({
    host: process.env.NODEMAILER_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASSWORD,
    },
  })

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
  }

  try {
    await transporter.sendMail(mailOptions)
    res.status(200).send('Email sent')
  } catch (error) {
    console.log(error)
    res.status(500).send('Error sending email')
  }
}

export const sendEmailSelect = async (req: Request, res: Response) => {
  console.log(req.body)
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    console.log(errors)
    return res.status(400).json({ errors: errors.array() })
  }

  const sanitizedMessage = sanitizeHtml(req.body.clarification)
  const sanitizedEmail = sanitizeHtml(req.body.email)
  const { favoriteHero, issues } = req.body

  let transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASSWORD,
    },
  })

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
  }

  try {
    await transporter.sendMail(mailOptions)
    res.status(200).send('Email sent')
  } catch (error) {
    console.log(error)
    res.status(500).send('Error sending email')
  }
}

export const sendVerificationLink = async (req: Request, res: Response) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    console.log(errors)
    return res.status(400).json({ errors: errors.array() })
  }
  const { email } = req.body
  const token = generateToken(email)

  let transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASSWORD,
    },
  })

  let mailOptions = {
    from: process.env.NODEMAILER_USER,
    to: email,
    subject: `Verify your email address for jenniina.fi`,
    text: `
            Click the link below to verify your email address.
            ${process.env.SITE_URL}/verify/${token}
        `,
  }

  try {
    await transporter.sendMail(mailOptions)
    res.status(200).send('Email sent')
  } catch (error) {
    console.log(error)
    res.status(500).send('Error sending email')
  }
}
