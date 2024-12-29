import express from "express";
import { Request, Response, NextFunction } from "express";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import AWS from "aws-sdk";
import * as crypto from "crypto";
import axios from "axios";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const connectionString = process.env.DB_URL;

const pool = new Pool({
    connectionString,
});

const query = async (text: string, params?: any[]) => {
    return pool.query(text, params);
}


const initializeDB = async () => {
    const Queries = [
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'Teacher'
        )`,
        `CREATE TABLE IF NOT EXISTS exams (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            marks INT NOT NULL,
            paper TEXT,
            encryption_key TEXT,
            encryption_iv TEXT,
            admin_id INT UNIQUE NOT NULL,
            creator_id INT UNIQUE NOT NULL,
            scheduled_time TIMESTAMP NOT NULL,
            FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS exam_teachers (
            id SERIAL PRIMARY KEY,
            exam_id INT NOT NULL,
            teacher_id INT NOT NULL,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        )`
    ];
    

    for(const sql of Queries) {
       try {
            await query(sql);
       } 
       catch(error) {
            console.log(error);
       }
    }
    console.log("DB Initialized");
};

const s3 = new AWS.S3({
    accessKeyId: process.env.ACCESS_KEY,
    secretAccessKey: process.env.SECRET_ACCESS,
    region: process.env.REGION,
});

const upload = multer({ storage: multer.memoryStorage() });

const encryptFile = (buffer: Buffer) => {
    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", encryptionKey,iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return {
        encryptedData: encrypted,
        key: encryptionKey.toString("hex"),
        iv: iv.toString("hex")
    }
}

const authMiddleware = async(req: Request, res: Response, next: NextFunction): Promise<any> => {
    const authHeader = req.headers.authorization;

    if(authHeader === undefined || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ message: "You must be authenticated 🙃" });
    }

    const authToken = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(authToken, String(process.env.JWT_SECRET));
        (<any>req).user = decoded;
        next();
    } catch (error) {
        next(error);
    }
}
app.post("/api/v1/register", async (req: Request, res: Response):Promise<any> => {
    const { name, email, rawPassword, role } = req.body;

    try {
        const existingUser: any = await query("SELECT * FROM users WHERE email = $1", [email]);
        if (existingUser.rowCount > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        const password = await bcrypt.hash(rawPassword, 10);

        const result = await query(
            "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id",
            [name, email, password, role || "Teacher"]
        );

        res.status(201).json({ userId: result.rows[0].id });
    } catch (error) {
        res.status(501).json({ message:"Internal Server error 🥲" });
    }    
});

app.post("/api/v1/login", async (req: Request, res: Response): Promise<any>  => {
    const { email, password } = req.body;
    try {
        const user = await query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rowCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const userInfo = user.rows[0];

        const isPasswordValid = await bcrypt.compare(password, userInfo.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign({ id: userInfo.id}, String(process.env.JWT_SECRET), { expiresIn: "1d" });
        res.json({ token });
    } catch (error) {
        res.status(501).json({ message:"Internal Server error 🥲" });
    }
});

app.post("/api/v1/addExam", authMiddleware, async (req: Request, res: Response): Promise<any> => {
    const { name, marks, teacher_ids, timestamp, creator_id } = req.body; // Added creator_id
    const client = await pool.connect();

    try {
        if (!name || typeof name !== "string") {
            return res.status(400).json({ message: "Invalid 'name' provided." });
        }
        if (!marks || typeof marks !== "number" || marks <= 0) {
            return res.status(400).json({ message: "Invalid 'marks' provided." });
        }
        if (!Array.isArray(teacher_ids) || !teacher_ids.every((id) => typeof id === "number")) {
            return res.status(400).json({ message: "Invalid 'teacher_ids' provided." });
        }
        if (!timestamp || isNaN(Date.parse(timestamp))) {
            return res.status(400).json({ message: "Invalid 'timestamp' provided." });
        }
        if (!creator_id || typeof creator_id !== "number") {
            return res.status(400).json({ message: "Invalid 'creator_id' provided." });
        }

        const creatorCheckQuery = `SELECT id FROM users WHERE id = $1`;
        const creatorResult = await client.query(creatorCheckQuery, [creator_id]);

        if (creatorResult.rowCount === 0) {
            return res.status(404).json({ message: "Creator with the given ID does not exist." });
        }

        await client.query("BEGIN");

        const insertExamQuery = `
            INSERT INTO exams (name, marks, creator_id, scheduled_time)
            VALUES ($1, $2, $3, $4)
            RETURNING id;
        `;
        const result = await client.query(insertExamQuery, [name, marks, creator_id, new Date(timestamp)]);
        const exam_id = result.rows[0].id;

        const insertTeachersQuery = `
            INSERT INTO exam_teachers (exam_id, teacher_id)
            VALUES ($1, $2)
        `;
        for (const teacher_id of teacher_ids) {
            await client.query(insertTeachersQuery, [exam_id, teacher_id]);
        }

        await client.query("COMMIT");
        res.status(201).json({ message: "Exam created successfully 🥳", exam_id });
    } catch (error) {
        await client.query("ROLLBACK");
        console.error(error);
        res.status(500).json({ message: "Internal Server Error 🥲" });
    } finally {
        client.release();
    }
});


app.post("/api/v1/addExamTeacher/:examId", authMiddleware, async (req: Request, res: Response): Promise<any> => {
    const { teacher_ids } = req.body;
    const examId  = parseInt(req.params.examId);
    const client = await pool.connect();
    const { id } = (<any>req).user;
    try {
        if (!Array.isArray(teacher_ids) || !teacher_ids.every((id) => typeof id === "number")) {
            return res.status(400).json({ message: "Invalid 'teacher_ids' provided." });
        }

        const examInfo = await client.query ("SELECT * FROM exams WHERE id = $1", [examId]);
        if(!examInfo) {
            res.status(404).json({ message: "No such exam exists 🥲" });
        }

        if(examInfo.rows[0].admin_id !== id) {
            return res.status(403).json({ message: "You have no rights to do this 🙃" });
        }
        const insertTeachersQuery = `
            INSERT INTO exam_teachers (exam_id, teacher_id)
            VALUES ($1, $2)
        `;

        for(const teacher_id of teacher_ids) {
            await client.query(insertTeachersQuery,[examId, teacher_id]);
        }

        res.status(201).json({ message: "Teacher added successfully 🥳" });
    } catch (error) {
        await client.query("ROLLBACK");
        console.error(error);
        res.status(500).json({ message: "Internal Server Error 🥲" });
    }
});

app.put("/api/v1/updateExam/:examId", authMiddleware, async(req: Request, res: Response): Promise<any> => {
    const examId = parseInt(req.params.examId);
    const {name, marks, timestamp, creator_id} = req.body;

    try {
        const updates: string[] = [];
        const values: any[] = [];
        let paramIndex = 1;

        if(name) {
            updates.push(`name = $${paramIndex++}`);
            values.push(name);
        }
        if(marks !== undefined) {
            updates.push(`marks = $${paramIndex++}`);
            values.push(parseInt(marks));
        }
        if (timestamp && !isNaN(Date.parse(timestamp))) {
            updates.push(`scheduled_time = $${paramIndex++}`);
            values.push(timestamp);
        }
        if(creator_id) {
            updates.push(`creator_id = $${paramIndex++}`);
            values.push(Number(creator_id));
        }

        values.push(Number(examId));

        const updateQuery = `
            UPDATE exam
            SET ${updates.join(", ")}
            WHERE id = $${paramIndex}
            RETURNING *;
        `;

        const result = await query(updateQuery, values);
        if(result.rowCount === 0) {
            res.status(404).json({ message: "No such exam exists 🥲" });
        }
        res.status(201).json({ message: "Exam updated successfully 🥳" });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error 🥲" });
    }
});

app.delete("/api/v1/exam/:exam_id/teacher/:teacher_id",authMiddleware, async (req: Request, res: Response): Promise<any> => {
        const { exam_id, teacher_id } = req.params;
        const client = await pool.connect();

        try {
            if (!exam_id || isNaN(parseInt(exam_id))) {
                return res.status(400).json({ message: "Invalid 'exam_id' provided." });
            }
            if (!teacher_id || isNaN(parseInt(teacher_id))) {
                return res.status(400).json({ message: "Invalid 'teacher_id' provided." });
            }

            const examCheckQuery = `SELECT id FROM exams WHERE id = $1`;
            const examResult = await client.query(examCheckQuery, [exam_id]);
            if (examResult.rowCount === 0) {
                return res.status(404).json({ message: "Exam not found." });
            }

            const teacherCheckQuery = `
                SELECT * FROM exam_teachers
                WHERE exam_id = $1 AND teacher_id = $2
            `;

            const teacherResult = await client.query(teacherCheckQuery, [exam_id, teacher_id]);
            if (teacherResult.rowCount === 0) {
                return res.status(404).json({ message: "Teacher is not assigned to this exam." });
            }

            const deleteQuery = `
                DELETE FROM exam_teachers
                WHERE exam_id = $1 AND teacher_id = $2
            `;

            await client.query(deleteQuery, [exam_id, teacher_id]);

            res.status(200).json({ message: `Teachers updated successfully 🥳` });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Internal Server Error 🥲" });
        } finally {
            client.release();
        }
    }
);

app.post("/api/v1/exams/:examId/uploadPaper", upload.single("file"), authMiddleware, async (req: Request, res: Response): Promise<any> => {
    const examId = Number(req.params.examId);
    const file = req.file;
    const userId = (<any>req).user.id;

    if(!file) {
        return res.status(400).json({ message: "No file provided." });
    }

    try {
        const examInfo = await query("SELECT * FROM exams WHERE id = $1", [examId]);
        
        if(examInfo.rowCount === 0) {
            return res.status(400).json({ message: "No such exam exists 🥲"});
        }

        if(examInfo.rows[0].creator_id !== userId) {
            return res.status(403).json({ message: "You have no rights to add paper 🧐"})
        }

        const {encryptedData, key, iv} = encryptFile(file.buffer);

        const s3Key = `exams/${examId}/${examInfo.rows[0].name}-Paper`;

        await s3.upload({
            Bucket: String(process.env.BUCKET),
            Key: s3Key,
            Body: encryptedData,
        }).promise();

        const s3Path = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;

        await query(`
            UPDATE exams
            SET paper = $1, encryption_key = $2, encryption_iv = $3
            where id = $4
        `, [s3Path, key, iv, examId]);
        
        res.status(201).json({ message: "Paper added succesfully 🥳"})
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error 🥲" });
    }
});

app.get("/api/vi/getDashboardData", authMiddleware, async(req: Request, res: Response): Promise<any> => {
    const id = Number((<any>req).user.id);

    try {
        const creatorExams = await query(`
            SELECT * FROM exams WHERE creator_id = $id;    
        `,[id]);
        const adminExams = await query(`
            SELECT * FROM exams WHERE admin_id = $id;
        `,[id]);
        const teacherExams = await query(`
            SELECT exams.*, users.name as creator_name, admins.name as admin_name
            FROM exam_teachers
            JOIN exams ON exam_teachers.exam_id = exams.id
            JOIN users ON exams.creator_id = users.id
            JOIN users as admins ON exams.admin_id = admins.id
            WHERE exam_teachers.teacher_id = $1;
        `,[id]);
        
        res.status(200).json({
            creatorExams: creatorExams.rows,
            adminExams: adminExams.rows,
            teacherExams: teacherExams.rows,
        });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error 🥲" });
    }
});

app.get("/api/v1/getExamById/:examId", authMiddleware, async(req: Request, res: Response): Promise<any> => {
    try {
        const exams = await query("SELECT * FROM exam WHERE id = $1",[Number(req.params.examId)]);
        return res.status(201).json({exams});
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error 🥲" });
    }
})

app.get("/api/v1/getPaper/:examId", authMiddleware, async(req: Request, res: Response): Promise<any> => {
    const examId = Number(req.params.examId);
    const userId = Number((<any>req).user.id);

    try {
        const examQuery = `
        SELECT exams.*, users.name as creator_name, admins.name as admin_name
            FROM exams
            JOIN users ON exams.creator_id = users.id
            JOIN users as admins ON exams.admin_id = admins.id
            WHERE exams.id = $1;
        `;
        const examResult = await query(examQuery, [examId]);

        if (examResult.rows.length === 0) {
            return res.status(404).json({ message: "Exam not found." });
        }

        
        const exam = examResult.rows[0];
        const currentTime = new Date();
        const scheduledTime = new Date(exam.scheduled_time);

        const examTeachers: any = await query("SELECT * FROM exam_teachers WHERE exam_id = $1", [examId]);
        if (
            userId !== exam.creator_id &&
            userId !== exam.admin_id 
        ) {
            return res.status(403).json({ message: "Access denied. Unauthorized." });
        }

        let flag = true;
        for(let i = 0 ; i < examTeachers.rowCount ; i++) {
            if(userId === examTeachers.rows[i].teacher_id) {
                flag = false;
            }
        }

        if(flag) {
            return res.status(403).json({ message: "Access denied. Unauthorized." });
        }

        if (currentTime < scheduledTime) {
            return res
                .status(400)
                .json({ message: "The paper is not accessible before the scheduled time." });
        }

        if (!exam.paper || !exam.encryption_key || !exam.encryption_iv) {
            return res.status(404).json({ message: "No paper or encryption data found for this exam." });
        }

        const s3Url = exam.paper;
        const encryptedResponse = await axios.get(s3Url, { responseType: "arraybuffer" });
        const encryptedBuffer = Buffer.from(encryptedResponse.data);

        const decipher = crypto.createDecipheriv(
            "aes-256-cbc",
            Buffer.from(exam.encryption_key, "hex"),
            Buffer.from(exam.encryption_iv, "hex")
        );
        const decryptedBuffer = Buffer.concat([
            decipher.update(encryptedBuffer),
            decipher.final(),
        ]);

        res.setHeader("Content-Type", "application/pdf");
        res.setHeader(
            "Content-Disposition",
            `attachment; filename=exam-${examId}.pdf`
        );
        res.end(decryptedBuffer);
    } catch (error) {
        
    }
})
initializeDB().then(() => {
    app.listen(PORT, () => { 
        console.log(`Server Up on ${PORT} 🚀`);
    });
})
.catch((error) => {
    console.log("Failed to initialize DB and Server due to ==>  " + error);
    process.exit(1);
});