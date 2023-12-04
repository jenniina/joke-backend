import { Document } from 'mongoose'

export interface IUser extends Document {
  _id?: string
  username: string
  password: string
  language: ELanguages
  verified?: boolean
  createdAt?: string
  updatedAt?: string
}
export enum ECategory {
  all = 'All',
  misc = 'Misc',
  programming = 'Programming',
  dark = 'Dark',
  pun = 'Pun',
  spooky = 'Spooky',
  christmas = 'Christmas',
}
export enum EJokeType {
  single = 'single',
  twopart = 'twopart',
}
export enum ELanguages {
  English = 'en',
  Spanish = 'es',
  French = 'fr',
  German = 'de',
  Portuguese = 'pt',
  Czech = 'cs',
}

export interface IJokeCommonFields {
  jokeId: number
  type: EJokeType
  category: ECategory
  language: ELanguages
  safe: boolean
  user: IUser['_id'][]
  createdAt?: string
  updatedAt?: string
}

export interface IJokeSingle extends IJokeCommonFields {
  type: EJokeType.single
  joke: string
}

export interface IJokeTwoPart extends IJokeCommonFields {
  type: EJokeType.twopart
  setup: string
  delivery: string
}

// export interface IJokeSingle extends Document {
//   jokeId: number
//   joke: string
//   type: EJokeType
//   category: ECategory
//   language: ELanguages
//   safe: boolean
//   user: IUser['_id'][]
//   createdAt?: string
//   updatedAt?: string
// }
// export interface IJokeTwoPart extends Document {
//   jokeId: number
//   setup: string
//   delivery: string
//   type: IJokeType
//   category: ECategory
//   language: ELanguages
//   safe: boolean
//   user: IUser['_id'][]
//   createdAt?: string
//   updatedAt?: string
// }
export type IJoke = IJokeSingle | IJokeTwoPart

export interface ITokenPayload {
  userId: string
}
export interface IToken {
  token: string
  createdAt: Date
}

export enum EQuizType {
  easy = 'easy',
  medium = 'medium',
  hard = 'hard',
}

export interface IQuiz extends Document {
  highscores: {
    easy: number
    medium: number
    hard: number
  }
  type: EQuizType
  user: IUser['_id']
  createdAt?: string
  updatedAt?: string
}
export interface IQuestion extends Document {
  questionId: number
  question: string
  options: string[]
  correctAnswer: boolean
  incorrectAnswers: boolean[]
  createdAt?: string
  updatedAt?: string
}
export interface IQuizQuestion extends Document {
  quiz: IQuiz['_id']
  question: IQuestion['_id']
  createdAt?: string
  updatedAt?: string
}
