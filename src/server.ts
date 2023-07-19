import app from "./app";
import dotenv from 'dotenv'

dotenv.config();

const port: number = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});