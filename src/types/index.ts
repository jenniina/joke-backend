import { Document } from 'mongoose'

export interface IUser extends Document {
  _id?: string
  name: string
  username: string
  password: string
  language: ELanguages
  role: number
  verified?: boolean
  token?: string
  resetToken?: string
  confirmToken?: string
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
  userId: string | undefined
  iat?: number
  exp?: number
}
export interface IToken {
  token: string | undefined
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

export interface ITodo extends Document {
  key: string
  name: string
  complete: boolean
  createdAt?: string
  updatedAt?: string
}

export interface ITodos extends Document {
  user: IUser['_id']
  todos: ITodo[]
  createdAt?: string
  updatedAt?: string
}

export enum ELanguage {
  en = 'en',
  es = 'es',
  fr = 'fr',
  de = 'de',
  pt = 'pt',
  cs = 'cs',
}
export enum EError {
  en = 'An error occurred',
  es = 'Ha ocurrido un error',
  fr = 'Une erreur est survenue',
  de = 'Ein Fehler ist aufgetreten',
  pt = 'Ocorreu um erro',
  cs = 'Došlo k chybě',
}

export enum EAnErrorOccurredAddingTheJoke {
  en = 'An error occurred adding the joke',
  es = 'Ha ocurrido un error al agregar la broma',
  fr = "Une erreur s'est produite lors de l'ajout de la blague",
  de = 'Beim Hinzufügen des Witzes ist ein Fehler aufgetreten',
  pt = 'Ocorreu um erro ao adicionar a piada',
  cs = 'Při přidávání vtipu došlo k chybě',
}
