import express, { Express, Request, Response } from "express";
import authRouter from "./routes/authRouter"

const app: Express = express();

app.use(express.json());

app.get('/', (req: Request, res: Response) => {
    res.json('insufficient data for meaningful answer')
});

app.use(authRouter);

export default app;