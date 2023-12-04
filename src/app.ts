import express, { Express } from 'express'
import mongoose, { ConnectOptions } from 'mongoose'
import cors from 'cors'
import jokeRoutes from './routes'

const app: Express = express()

const PORT: string | number = process.env.PORT || 4000

app.use(cors())
app.use(express.json())
app.use(jokeRoutes)

const uri: string = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_CLUSTER}.zzpvtsc.mongodb.net/${process.env.MONGO_DB}?retryWrites=true&w=majority`
const options = { useNewUrlParser: true, useUnifiedTopology: true }

mongoose
  //.connect(uri, options as ConnectOptions)
  //.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true } as ConnectOptions)
  .connect(uri)
  .then(() =>
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`))
  )
  .catch((error) => {
    throw error
  })
