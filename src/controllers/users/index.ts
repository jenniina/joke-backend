import { Response, Request } from 'express'
import bcrypt from 'bcrypt'
import { IUser } from '../../types'
import { User } from '../../models/user'
import { ITokenPayload, IToken } from '../../types'
import jwt, { Secret } from 'jsonwebtoken'

const generateToken = (userId: string): string => {
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
    res.status(500).json({ message: 'An error occurred' })
  }
}

const getUsers = async (req: Request, res: Response): Promise<void> => {
  try {
    const users: IUser[] = await User.find()
    res.status(200).json({ users })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const getUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const user: IUser | null = await User.findById(req.params.id)
    res.status(200).json({ user })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
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
    res.status(500).json({ message: 'An error occurred' })
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
    res.status(500).json({ success: false, message: 'An error occurred' })
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
//     res.status(500).json({ message: 'An error occurred' })
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
    res.status(500).json({ message: 'An error occurred' })
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
  }

  try {
    const { username, password } = req.body
    const user: IUser | null = await User.findOne({ username })

    if (!user) {
      res.status(401).json({ message: 'User not found' })
    } else if (!user.verified) {
      res.status(401).json({ message: 'User not verified. Please check your email' })
    } else {
      const passwordMatch: boolean = await comparePassword.call(user, password)

      if (passwordMatch) {
        res.status(200).json({ user })
      } else {
        res.status(401).json({ message: 'Invalid login credentials' })
      }
    }
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
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
//     res.status(500).json({ message: 'An error occurred' })
//   }
// }

const registerUser = async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password, jokes, language } = req.body
    const saltRounds = 10
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    const user: IUser | null = await User.findOne({ username })
    if (user) {
      res.status(401).json({ message: 'User already exists' })
    } else {
      const newUser: IUser = new User({
        username,
        password: hashedPassword,
        jokes,
        language,
        verified: false,
      })

      await newUser.save()
      res.status(201).json({
        message: 'User registered. Please check your email for the verification link',
      })
    }
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const findUserByUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    const userByUsername: IUser | null = await User.findOne({
      username: req.params.username,
    })
    res.status(200).json({ user: userByUsername })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
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
    res.status(500).json({ message: 'An error occurred' })
  }
}

const checkSession = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Session checked' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const forgotPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password forgot' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password reset' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetPasswordToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password reset with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changePassword = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changePasswordToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Password changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const verifyEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email verified' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const verifyEmailToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email verified with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const forgotEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email forgot' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email reset' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetEmailToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email reset with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changeEmail = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changeEmailToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Email changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const verifyUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username verified' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const verifyUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username verified with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const forgotUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username forgot' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username reset' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const resetUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username reset with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changeUsername = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username changed' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

const changeUsernameToken = async (req: Request, res: Response): Promise<void> => {
  try {
    res.status(200).json({ message: 'Username changed with token' })
  } catch (error) {
    console.error('Error:', error)
    res.status(500).json({ message: 'An error occurred' })
  }
}

export {
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
  forgotEmail,
  resetEmail,
  resetEmailToken,
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
