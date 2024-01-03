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
  chucknorris = 'ChuckNorris',
  dadjokes = 'DadJokes',
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
  Suomi = 'fi',
}

export interface IJokeCommonFields {
  _id?: string
  jokeId: string
  type: EJokeType
  category: ECategory
  subCategories: string[]
  language: string
  safe: boolean
  flags: {
    nsfw?: boolean
    religious?: boolean
    political?: boolean
    racist?: boolean
  }
  user: IUser['_id'][]
  private?: boolean
  verified?: boolean
  anonymous?: boolean
  author?: string
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
  fi = 'fi',
}
export enum EError {
  en = 'An error occurred',
  es = 'Ha ocurrido un error',
  fr = 'Une erreur est survenue',
  de = 'Ein Fehler ist aufgetreten',
  pt = 'Ocorreu um erro',
  cs = 'Došlo k chybě',
  fi = 'Tapahtui virhe',
}

export enum EAnErrorOccurredAddingTheJoke {
  en = 'An error occurred adding the joke',
  es = 'Ha ocurrido un error al agregar la broma',
  fr = "Une erreur s'est produite lors de l'ajout de la blague",
  de = 'Beim Hinzufügen des Witzes ist ein Fehler aufgetreten',
  pt = 'Ocorreu um erro ao adicionar a piada',
  cs = 'Při přidávání vtipu došlo k chybě',
  fi = 'Vitsin lisäämisessä tapahtui virhe',
}
// Email sent to administrator, please wait for approval
export enum EEmailSentToAdministratorPleaseWaitForApproval {
  en = 'Email sent to administrator, please wait for approval',
  es = 'Correo electrónico enviado al administrador, espere la aprobación',
  fr = 'Email envoyé à l administrateur, veuillez attendre l approbation',
  de = 'E-Mail an Administrator gesendet, bitte warten Sie auf Genehmigung',
  pt = 'E-mail enviado ao administrador, aguarde a aprovação',
  cs = 'E-mail odeslán správci, počkejte na schválení',
  fi = 'Sähköposti lähetetty ylläpitäjälle, odota hyväksyntää',
}
export enum EJokeUpdated {
  en = 'Joke updated',
  es = 'Broma actualizada',
  fr = 'Blague mise à jour',
  de = 'Witz aktualisiert',
  pt = 'Piada atualizada',
  cs = 'Vtip aktualizován',
  fi = 'Vitsi päivitetty',
}
// 'User deleted from joke'
export enum EUserDeletedFromJoke {
  en = 'User deleted from joke',
  es = 'Usuario eliminado de la broma',
  fr = 'Utilisateur supprimé de la blague',
  de = 'Benutzer aus Witz gelöscht',
  pt = 'Usuário excluído da piada',
  cs = 'Uživatel smazán z vtipu',
  fi = 'Käyttäjä poistettu vitsistä',
}
