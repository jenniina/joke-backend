import { IUser } from '../types'
import { model, Schema } from 'mongoose'

const userSchema: Schema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      minlength: 3,
    },
    name: {
      type: String,
      required: false,
      minlength: 2,
    },
    password: {
      type: String,
      required: true,
      minlength: 3,
    },
    language: {
      type: String,
      required: false,
      minlength: 2,
    },
    verified: {
      type: Boolean,
      required: true,
      default: false,
    },
  },
  { timestamps: true }
)

export const User = model<IUser>('User', userSchema)
