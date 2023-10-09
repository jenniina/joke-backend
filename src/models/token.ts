import { model, Schema } from 'mongoose'

const tokenSchema: Schema = new Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true,
    },
    createdAt: {
      type: Date,
      expires: 3600,
      default: Date.now,
    },
  },
  { timestamps: true }
)

export const Token = model('Token', tokenSchema)
