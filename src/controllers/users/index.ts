import { Response, Request, NextFunction } from 'express'
import bcrypt from 'bcrypt'
import { IUser } from '../../types'
import { User } from '../../models/user'
import { ITokenPayload, IToken } from '../../types'
import jwt, { Secret } from 'jsonwebtoken'
const dotenv = require('dotenv')
dotenv.config()

const nodemailer = require('nodemailer')

const transporter = nodemailer.createTransport({
  host: `${process.env.EMAIL_SERVICE}`,
  port: `${process.env.EMAIL_PORT}`,
  secure: false,
  auth: {
    user: `${process.env.EMAIL_USER}`,
    pass: `${process.env.EMAIL_PASSWORD}`,
  },
})

enum EError {
  en = 'An error occurred',
  es = 'Ha ocurrido un error',
  fr = 'Une erreur est survenue',
  de = 'Ein Fehler ist aufgetreten',
  pt = 'Ocorreu um erro',
  cs = 'Došlo k chybě',
}
enum ELanguage {
  en = 'en',
  es = 'es',
  fr = 'fr',
  de = 'de',
  pt = 'pt',
  cs = 'cs',
}
enum ETheComediansCompanion {
  en = "The Comedian's Companion",
  es = 'El Compañero del Comediante',
  fr = 'Le Compagnon du Comédien',
  de = 'Der Begleiter des Komikers',
  pt = 'O Companheiro do Comediante',
  cs = 'Společník komika',
}
enum EBackToTheApp {
  en = 'Back to the App',
  es = 'Volver a la aplicación',
  fr = 'Retour à l application',
  de = 'Zurück zur App',
  pt = 'Voltar para o aplicativo',
  cs = 'Zpět do aplikace',
}

const generateToken = (userId: string | undefined): string | undefined => {
  if (!userId) return undefined
  const payload: ITokenPayload = { userId }
  const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
  const options = { expiresIn: '1d' }
  return jwt.sign(payload, secret, options) as IToken['token']
}

const verifyToken = (token: string): ITokenPayload => {
  const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'
  return jwt.verify(token, secret) as ITokenPayload
}

const verifyTokenMiddleware = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.split(' ')[1] as IToken['token']
    if (!token) throw new Error('No token provided')
    const decoded = verifyToken(token)
    const user: IUser | null = await User.findById(decoded.userId)
    if (!user) throw new Error('User not found')
    res.status(200).json({ message: 'Token verified' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

// Middleware to check if the user has admin role
const checkIfAdmin = (req: Request, res: Response, next: NextFunction) => {
  const user = req.body
  if (user && user.role > 2) {
    // User is an admin, allow access
    next()
  } else {
    // User is not an admin, deny access
    res.status(403).json({ message: 'Access denied. Admin privilege required.' })
  }
}

const authenticateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) throw new Error('No token provided')

    const decoded = verifyToken(token)
    const user: IUser | null = await User.findById(decoded.userId)

    if (!user) throw new Error('User not authenticated')

    // Attach user information to the request object
    req.body = user
    next()
  } catch (error) {
    console.error('Error:', error)
    res.status(401).json({ message: 'Authentication failed' })
  }
}

const getUsers = async (req: Request, res: Response): Promise<void> => {
  try {
    const users: IUser[] = await User.find()
    res.status(200).json({ users })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const getUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const user: IUser | null = await User.findById(req.params.id)
    res.status(200).json(user)
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const addUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const body = req.body as Pick<IUser, 'username' | 'password' | 'language'>

    const user: IUser = new User({
      username: body.username,
      password: body.password,
      language: body.language,
      verified: false,
    })

    const newUser: IUser = await user.save()
    const allUsers: IUser[] = await User.find()

    res.status(201).json({ message: 'User added', user: newUser, users: allUsers })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const updateUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      params: { id: _id },
      body,
    } = req

    const updateUser: IUser | null = await User.findByIdAndUpdate(
      { _id: _id },
      { new: true }
    )
    //const updateUser: IUser | null = await User.findByIdAndUpdate({ _id: _id }, body)

    const allUsers: IUser[] = await User.find()
    res.status(200).json({
      success: true,
      message: 'User updated',
      user: updateUser,
    })
  } catch (error) {
    console.error('Error:', error)
    res
      .status(500)
      .json({ success: false, message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

// const updateUserJokes = async (req: Request, res: Response) => {
//   try {
//     const { id: _id } = req.params
//     const { jokeId }: { jokeId: number | undefined } = req.body

//     // Find the user by ID
//     const user = await User.findById(_id)

//     if (!user) {
//       res.status(404).json({ message: 'User not found' })
//       return
//     }

//     // Check if the 'jokeId' already exists in the 'jokes' array
//     if (!user.jokes.includes(jokeId! as never)) {
//       user.jokes.push(jokeId! as never)
//       await user.save()
//     }

//     res.status(200).json({ message: 'User jokes updated successfully', user })
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//   }
// }

const deleteUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const deletedUser: IUser | null = await User.findByIdAndRemove(req.params.id)
    const allUsers: IUser[] = await User.find()
    res.status(200).json({
      message: 'User deleted',
      user: deletedUser,
      users: allUsers,
    })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const loginUser = async (req: Request, res: Response): Promise<void> => {
  const comparePassword = async function (
    this: IUser,
    candidatePassword: string
  ): Promise<boolean> {
    try {
      const isMatch: boolean = await bcrypt.compare(candidatePassword, this.password!)
      return isMatch
    } catch (error) {
      console.error('Error:', error)
      return false
    }
  } //

  try {
    const { username, password } = req.body
    const user: IUser | null = await User.findOne({ username })

    if (!user) {
      res.status(401).json({ message: 'Invalid login credentials-' })
    } else if (!user.verified) {
      res.status(401).json({ message: 'User not verified. Please check your email' })
    } else {
      const passwordMatch: boolean = await comparePassword.call(user, password)

      if (passwordMatch) {
        const token = generateToken(user._id)
        res.status(200).json({ message: 'Successfully logged in', user, token })
      } else {
        res.status(401).json({ message: 'Invalid login credentials' })
      }
    }
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

// const loginUser = async (req: Request, res: Response): Promise<void> => {
//   const comparePassword = async function (
//     this: IUser,
//     candidatePassword: string
//   ): Promise<boolean> {
//     try {
//       const isMatch: boolean = await bcrypt.compare(candidatePassword, this.password!)
//       return isMatch
//     } catch (error) {
//       console.error('Error:', error)
//       return false
//     }
//   }
//   try {
//     const { username, password } = req.body
//     const user: IUser | null = await User.findOne({ username })
//     if (!user) {
//       res.status(401).json({ message: 'User not found' })
//     } else if (!user.verified) {
//       res.status(401).json({ message: 'User not verified. Please check your email' })
//     } else {
//       const passwordMatch: boolean = await comparePassword.call(user, password)
//       if (passwordMatch) {
//         res.status(200).json({ message: 'User logged in' })
//       } else {
//         res.status(401).json({ message: 'Invalid login credentials' })
//       }
//     }
//   } catch (error) {
//     console.error('Error:', error)
//     res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//   }
// }

const registerUser = async (req: Request, res: Response): Promise<void> => {
  //User.collection.dropIndex('jokes_1')
  // try {
  enum EHelloWelcome {
    en = "Hello, welcome to the Comedian's Companion",
    es = 'Hola, bienvenido al Compañero del Comediante',
    fr = 'Bonjour, bienvenue au Compagnon du Comédien',
    de = 'Hallo, willkommen beim Begleiter des Komikers',
    pt = 'Olá, bem-vindo ao Companheiro do Comediante',
    cs = 'Ahoj, vítejte u Společníka komika',
  }
  enum EEmailMessage {
    en = 'Please verify your email',
    es = 'Por favor verifica tu correo electrónico',
    fr = 'Veuillez vérifier votre email',
    de = 'Bitte überprüfen Sie Ihre E-Mail',
    pt = 'Por favor, verifique seu email',
    cs = 'Prosím, ověřte svůj email',
  }
  enum EMessage {
    en = 'User registered. Please check your email for the verification link',
    es = 'Usuario registrado. Por favor, compruebe su correo electrónico para el enlace de verificación',
    fr = 'Utilisateur enregistré. Veuillez vérifier votre email pour le lien de vérification',
    de = 'Benutzer registriert. Bitte überprüfen Sie Ihre E-Mail für den Bestätigungslink',
    pt = 'Usuário registrado. Por favor, verifique seu email para o link de verificação',
    cs = 'Uživatel registrován. Prosím, zkontrolujte svůj email pro ověřovací odkaz',
  }
  enum EErrorSendingMail {
    en = 'Error sending mail',
    es = 'Error al enviar el correo',
    fr = 'Erreur lors de l envoi du mail',
    de = 'Fehler beim Senden der E-Mail',
    pt = 'Erro ao enviar email',
    cs = 'Chyba při odesílání emailu',
  }

  const { username, password, jokes, language } = req.body
  const saltRounds = 10

  enum ERegistrationFailed {
    en = 'Registration failed',
    es = 'Registro fallido',
    fr = 'Inscription échouée',
    de = 'Registrierung fehlgeschlagen',
    pt = 'Registro falhou',
    cs = 'Registrace se nezdařila',
  }
  enum EErrorCreatingToken {
    en = 'Error creating token',
    es = 'Error al crear el token',
    fr = 'Erreur lors de la création du jeton',
    de = 'Fehler beim Erstellen des Tokens',
    pt = 'Erro ao criar token',
    cs = 'Chyba při vytváření tokenu',
  }
  try {
    bcrypt
      .hash(password, saltRounds)
      .then((hashedPassword) => {
        return User.findOne({ username }).then((user) => {
          if (user) {
            res.status(401).json({
              message: ERegistrationFailed[user.language] || 'Registration failed',
            })
          } else {
            const newUser = new User({
              username,
              password: hashedPassword,
              jokes,
              language,
              verified: false,
            })

            const secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'

            jwt.sign(
              { userId: newUser._id },
              secret,
              { expiresIn: '1d' },
              (err, token) => {
                if (err) {
                  console.error(err)
                  res.status(500).json({
                    message:
                      EErrorCreatingToken[newUser?.language] || 'Error creating token',
                  })
                } else {
                  const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${language}`
                  newUser.token = token

                  const sendMail = () => {
                    return new Promise((resolve, reject) => {
                      transporter.sendMail(
                        {
                          from: process.env.EMAIL_USER,
                          to: username,
                          subject: EHelloWelcome[language as ELanguage] || 'Welcome',
                          text:
                            EEmailMessage[language as ELanguage] + link ||
                            'Please verify your email' + link,
                        },
                        (error: any, info: { response: unknown }) => {
                          if (error) {
                            console.log(error)
                            reject(error)
                            res.status(500).json({
                              message:
                                EErrorSendingMail[language as ELanguage] ||
                                'Error sending mail',
                            })
                          } else {
                            console.log('Email sent: ' + info.response)
                            resolve(info.response)
                          }
                        }
                      )
                    })
                  }

                  sendMail()
                    .then((result) => {
                      newUser.save().then((user: IUser) => {
                        console.log('resulT', result)
                        console.log('user', user)
                        res.status(201).json({
                          user,
                          message: EMessage[language as ELanguage] || 'User registered',
                        })
                      })
                    })
                    .catch((error) => {
                      console.log(error)
                      res.status(500).json({
                        message:
                          EErrorSendingMail[language as ELanguage] ||
                          'Error sending mail',
                      })
                    })
                }
              }
            )
          }
        })
      })
      .catch((error) => {
        console.error('Error:', error)
        const language = req.body.language || 'en'
        res
          .status(500)
          .json({ message: EError[language as ELanguage] || 'An error occurred *' })
      })
  } catch (error) {
    console.error('Error:', error)
    const language = req.body.language || 'en'
    res
      .status(500)
      .json({ message: EError[language as ELanguage] || 'An error occurred ¤' })
  }
}
// const hashedPassword = await bcrypt.hash(password, saltRounds)
//     const user: IUser | null = await User.findOne({ username })
//     if (user) {
//       res.status(401).json({ message: 'Cannot register' })
//     } else {
//       const newUser: IUser = new User({
//         username,
//         password: hashedPassword,
//         jokes,
//         language,
//         verified: false,
//       })

//       enum EHelloWelcome {
//         en = "Hello, welcome to the Comedian's Companion",
//         es = 'Hola, bienvenido al Compañero del Comediante',
//         fr = 'Bonjour, bienvenue au Compagnon du Comédien',
//         de = 'Hallo, willkommen beim Begleiter des Komikers',
//         pt = 'Olá, bem-vindo ao Companheiro do Comediante',
//         cs = 'Ahoj, vítejte u Společníka komika',
//       }
//       enum EEmailMessage {
//         en = 'Please verify your email',
//         es = 'Por favor verifica tu correo electrónico',
//         fr = 'Veuillez vérifier votre email',
//         de = 'Bitte überprüfen Sie Ihre E-Mail',
//         pt = 'Por favor, verifique seu email',
//         cs = 'Prosím, ověřte svůj email',
//       }
//       enum EMessage {
//         en = 'User registered. Please check your email for the verification link',
//         es = 'Usuario registrado. Por favor, compruebe su correo electrónico para el enlace de verificación',
//         fr = 'Utilisateur enregistré. Veuillez vérifier votre email pour le lien de vérification',
//         de = 'Benutzer registriert. Bitte überprüfen Sie Ihre E-Mail für den Bestätigungslink',
//         pt = 'Usuário registrado. Por favor, verifique seu email para o link de verificação',
//         cs = 'Uživatel registrován. Prosím, zkontrolujte svůj email pro ověřovací odkaz',
//       }

//       const secret: Secret = process.env.JWT_SECRET || 'jgtrshdjfshdf'

//       const token = jwt.sign({ userId: newUser._id }, secret, { expiresIn: '1d' })

//       const link = `${process.env.BASE_URI}/api/users/verify/${token}?lang=${language}`

//       newUser.token = token

//       const sendMail = (): Promise<any> => {
//         return new Promise((resolve, reject) => {
//           transporter.sendMail(
//             {
//               from: `${process.env.EMAIL_USER}`,
//               to: username,
//               subject: EHelloWelcome[language as ELanguage],
//               text: `${EEmailMessage[language as ELanguage]}: ${link}`,
//             },
//             (error: Error | null, info: any) => {
//               if (error) {
//                 console.log(error)
//                 reject(error)
//                 res
//                   .status(500)
//                   .json({ message: EError[(req.body.language as ELanguage) || 'en'] })
//               } else {
//                 console.log('Email sent: ' + info.response)
//                 resolve(info.response)
//                 res.status(201).json({
//                   message: EMessage[language as ELanguage],
//                 })
//               }
//             }
//           )
//         })
//       }
//       enum EErrorSendingMail {
//         en = 'Error sending mail',
//         es = 'Error al enviar el correo',
//         fr = 'Erreur lors de l envoi du mail',
//         de = 'Fehler beim Senden der E-Mail',
//         pt = 'Erro ao enviar email',
//         cs = 'Chyba při odesílání emailu',
//       }
//       sendMail()
//         .then((result) => {
//           newUser.save()
//           console.log(result)
//         })
//         .catch((error) => {
//           console.log(error)
//           res.status(500).json({
//             message: EErrorSendingMail[(req.body.language as ELanguage) || 'en'],
//           })
//         })

//       // await transporter.sendMail({
//       //   from: `${process.env.EMAIL_USER}`,
//       //   to: username,
//       //   subject: EHelloWelcome[language as ELanguage],
//       //   text: `${EEmailMessage[language as ELanguage]}: ${link}`,
//       // })

//       // res.status(201).json({
//       //   message: EMessage[language as ELanguage],
//       // })
//     }
//   } catch (error) {
//     console.error('Error:', error)
//     const language = req.body.language || 'en'
//     res.status(500).json({ error, message: EError[language as ELanguage] })
//   }
// }

const verifyEmailToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.params.token
    const user = await User.findOne({ token: token })

    if (user) {
      // Mark the user as verified and remove the verification token
      user.verified = true
      user.token = undefined
      await user.save()

      //res.redirect('/api/users/verification-success')

      enum EVerificationSuccessful {
        en = 'Verification Successful',
        es = 'Verificación exitosa',
        fr = 'Vérification réussie',
        de = 'Verifizierung erfolgreich',
        pt = 'Verificação bem-sucedida',
        cs = 'Úspěšná verifikace',
      }

      enum EAccountSuccessfullyVerified {
        en = 'Your account has been successfully verified',
        es = 'Su cuenta ha sido verificada con éxito',
        fr = 'Votre compte a été vérifié avec succès',
        de = 'Ihr Konto wurde erfolgreich verifiziert',
        pt = 'Sua conta foi verificada com sucesso',
        cs = 'Váš účet byl úspěšně ověřen',
      }

      // let urlParams =
      //   typeof window !== 'undefined'
      //     ? new URLSearchParams(window.location.search)
      //     : undefined
      // let language = urlParams?.get('lang')

      const language = req.query.lang || 'en'
      const htmlResponse = `
    <html lang=${language ?? 'en'}>
      <head>
      
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style> 
        @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
          body {
            font-family: Lato, Helvetica, Arial, sans-serif;
            background-color: hsl(219, 100%, 10%);
            color: white;
            letter-spacing: -0.03em;
            display:flex;
            justify-content:center;
            align-items:center;
            min-height: 100vh;
          }
          body > div {
            margin: 0 auto;
            max-width: 800px;  
          }
          h1 {
            font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
            text-align: center;
          }
          p {
            font-size: 18px;
            text-align: center;
          }
          a {
            color: white;
          }
        </style>
        <title>
        ${
          ETheComediansCompanion[language as ELanguage] ?? "The Comedian' Companion"
        }</title>
      </head>
      <body>
      <div>
        <h1>${
          EVerificationSuccessful[language as ELanguage] ?? 'Verification successful'
        }</h1>
        <p>${
          EAccountSuccessfullyVerified[language as ELanguage] ??
          'Account successfully verified'
        }.</p>
        <p>
        <a href="https://react-az.jenniina.fi">${
          EBackToTheApp[language as ELanguage] ?? 'Back to the app'
        }</a>
        </p>
      </div>
      </body>
    </html>
  `
      res.send(htmlResponse)
    } else {
      const language = req.query.lang || 'en'

      enum EVerificationFailed {
        en = 'Already verified or verification token expired',
        es = 'Ya verificado o token de verificación caducado',
        fr = 'Déjà vérifié ou jeton de vérification expiré',
        de = 'Bereits verifiziert oder Verifizierungstoken abgelaufen',
        pt = 'Já verificado ou token de verificação expirado',
        cs = 'Již ověřeno nebo vypršel ověřovací token',
      }
      // const urlParams =
      //   typeof window !== 'undefined'
      //     ? new URLSearchParams(window.location.search)
      //     : undefined
      // const language = urlParams?.get('lang')

      const htmlResponse = `
    <html lang=${language ?? 'en'}>
      <head>
        <style> 
        @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
          body {
            font-family: Lato, Helvetica, Arial, sans-serif;
            background-color: hsl(219, 100%, 10%);
            color: white;
            letter-spacing: -0.03em;
            display:flex;
            justify-content:center;
            align-items:center;
            min-height: 100vh;
          }
          body > div {
            margin: 0 auto;
            max-width: 800px; 
          }
          h1 {
            font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
            text-align: center;
          }
          p {
            font-size: 18px;
            text-align: center;
          }
          a {
            color: white;
          }
        </style> 
      </head>
      <body>
      <div>
        <h1>${EVerificationFailed[language as ELanguage]}</p>
        <p>
        <a href="https://react-az.jenniina.fi">${
          EBackToTheApp[language as ELanguage] ?? 'Back to the app'
        }</a>
        </p>
      </div>
      </body>
    </html>
  `
      res.send(htmlResponse)
      //res.status(400).json({ message: 'Invalid verification token' })
    }
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

// const verificationSuccess = async (req: Request, res: Response): Promise<void> => {
//   const urlParams = new URLSearchParams(window.location.search)
//   const language = urlParams.get('lang')

//   enum EVerificationSuccessful {
//     en = 'Verification Successful',
//     es = 'Verificación exitosa',
//     fr = 'Vérification réussie',
//     de = 'Verifizierung erfolgreich',
//     pt = 'Verificação bem-sucedida',
//     cs = 'Úspěšná verifikace',
//   }

//   enum EAccountSuccessfullyVerified {
//     en = 'Your account has been successfully verified',
//     es = 'Su cuenta ha sido verificada con éxito',
//     fr = 'Votre compte a été vérifié avec succès',
//     de = 'Ihr Konto wurde erfolgreich verifiziert',
//     pt = 'Sua conta foi verificada com sucesso',
//     cs = 'Váš účet byl úspěšně ověřen',
//   }

//   enum EBackToTheApp {
//     en = 'Back to the App',
//     es = 'Volver a la aplicación',
//     fr = 'Retour à l application',
//     de = 'Zurück zur App',
//     pt = 'Voltar para o aplicativo',
//     cs = 'Zpět do aplikace',
//   }

//   const htmlResponse = `
//     <html lang=${language ?? 'en'}>
//       <head>
//         <meta charset="UTF-8">
//         <meta name="viewport" content="width=device-width, initial-scale=1.0">
//         <style>
//         @import url('https://fonts.googleapis.com/css2?family=Caveat&family=Oswald:wght@500;600&display=swap');
//         @import url('https://fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
//           body {
//             font-family: Lato, Helvetica, Arial, sans-serif;
//             background-color: hsl(219, 100%, 10%);
//             color: white;
//             letter-spacing: -0.03em;
//             display:flex;
//             justify-content:center;
//             align-items:center;
//             min-height: 100vh;
//           }
//           body > div {
//             margin: 0 auto;
//             max-width: 800px;
//           }
//           h1 {
//             font-family: Oswald, Lato, Helvetica, Arial, sans-serif;
//           }
//           p {
//             font-size: 18px;
//           }
//         </style>
//         <title>${ETheComediansCompanion[language as ELanguage]}</title>
//       </head>
//       <body>
//       <div>
//         <h1>${EVerificationSuccessful[language as ELanguage]}</h1>
//         <p>${EAccountSuccessfullyVerified}.</p>
//         <p>
//         <a href="https://react-az.jenniina.fi">${EBackToTheApp[language as ELanguage]}</a>
//         </p>
//       </div>
//       </body>
//     </html>
//   `
//   res.send(htmlResponse)
// }

const findUserByUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    const userByUsername: IUser | null = await User.findOne({
      username: req.params.username,
    })
    res.status(200).json({ user: userByUsername })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}
// const findUserByUsername = async (username: string): Promise<IUser | null> => {
//   try {
//     const userByUsername = await User.findOne({ username })
//     return userByUsername || null
//   } catch (error) {
//     console.error('Error:', error)
//     return null
//   }
// }

const logoutUser = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'User logged out' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const checkSession = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Session checked' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const forgotPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password forgot' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const resetPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password reset' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const resetPasswordToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password reset with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changePassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changePasswordToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const verifyEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email verified' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changeEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changeEmailToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const verifyUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username verified' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const verifyUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username verified with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const forgotUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username forgot' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const resetUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username reset' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const resetUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username reset with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changeUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

const changeUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: EError[(req.body.language as ELanguage) || 'en'] })
  }
}

export {
  // verificationSuccess,
  checkIfAdmin,
  authenticateUser,
  getUsers,
  getUser,
  addUser,
  updateUser,
  deleteUser,
  loginUser,
  registerUser,
  logoutUser,
  checkSession,
  forgotPassword,
  resetPassword,
  resetPasswordToken,
  changePassword,
  changePasswordToken,
  verifyEmail,
  verifyEmailToken,
  changeEmail,
  changeEmailToken,
  verifyUsername,
  verifyUsernameToken,
  forgotUsername,
  resetUsername,
  resetUsernameToken,
  changeUsername,
  changeUsernameToken,
  generateToken,
  verifyTokenMiddleware,
  verifyToken,
  findUserByUsername,
}
