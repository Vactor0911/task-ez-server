import express, { Request, Response } from "express";
import cors from "cors";
import MariaDB from 'mariadb';
import bcrypt from 'bcrypt'; // 비밀번호 암호화 최신버전 express 에서 가지고 있다함
import dotenv from 'dotenv'; // 환경 변수 사용한 민감한 정보 관리


// .env 파일 로드
dotenv.config();

const PORT = 3005; // 서버가 실행될 포트 번호

const app = express();
app.use(cors());
app.use(express.json());  // JSON 요청을 처리하기 위한 미들웨어

// MariaDB 연결 (createPool 사용)
const db = MariaDB.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10,
  bigNumberStrings: true,
});

console.log(process.env.DB_HOST, process.env.DB_PORT, process.env.DB_USERNAME, process.env.DB_PASSWORD, process.env.DB_NAME);

// MariaDB 연결 확인
db.getConnection()
    .then(conn => {
        console.log("task-ez 데이터베이스가 성공적으로 연결되었습니다");
        conn.release();
    })
    .catch(err => {
        console.error("데이터베이스 연결에 실패하였습니다.", err.message);
    });


// 기본 라우트 설정
app.get("/", (req, res) => {
  res.send("Task Ez Web Server!");
});

// 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});


// *** 사용자 로그인 API 시작
app.post('/api/login', (req: Request, res: Response) => {
  const { id, password } = req.body;

  console.log("로그인 요청 받은 데이터:", { id, password });

  // Step 1: 이메일로 사용자 조회
  db.query('SELECT * FROM user WHERE id = ?', [id])
    .then((rows: any) => {
      console.log("사용자 조회 결과:", rows);

      if (rows.length === 0) {
        // 사용자가 없는 경우
        console.log("사용자를 찾을 수 없습니다:", id);
        return res.status(401).json({
          success: false,
          message: '사용자를 찾을 수 없습니다. 회원가입 후 이용해주세요.',
        });
      }

      const user = rows[0];

      // Step 3: 암호화된 비밀번호 비교
      return bcrypt.compare(password, user.password).then((isPasswordMatch) => {
        if (!isPasswordMatch) {
          console.log("비밀번호가 일치하지 않습니다");
          return res.status(401).json({
            success: false,
            message: '비밀번호가 일치하지 않습니다',
          });
        }

        // Step 4: 로그인 성공 처리
        const nickname = user.name; // DB의 name 필드를 닉네임으로 사용
        console.log(`[${id}] ${nickname}님 로그인 성공`);
        res.json({
          success: true,
          message: '로그인 성공',
          nickname: nickname, // 닉네임 반환
        });
      });
    })
    .catch((err) => {
      // 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: '서버 오류 발생',
        error: err.message,
      });
    });
}); // 사용자 로그인 API 끝


// *** 로그아웃 API 수정 ***
app.post('/api/logout', async (req: Request, res: Response) => {
  const { id } = req.body;

  console.log("로그아웃 요청 받은 데이터:", { id });

  try {
    // Step 1: 사용자 조회
    const rows = await db.query("SELECT * FROM user WHERE id = ?", [id]);

    if (rows.length === 0) {
      // 사용자 정보를 찾지 못한 경우
      res.status(404).json({ success: false, message: "사용자를 찾을 수 없습니다." });
      return;
    }

    console.log(`[${id}] 님의 로그아웃이 성공적으로 완료되었습니다.`);

    // Step 4: 성공 응답 반환
    res.status(200).json({ success: true, message: "로그아웃이 성공적으로 완료되었습니다." });
  } catch (err) {
    // Step 5: 에러 처리
    console.error("로그아웃 처리 중 오류 발생:", err);
    res.status(500).json({ success: false, message: "로그아웃 처리 중 오류가 발생했습니다." });
  }
}); // 로그아웃 API 끝 



// *** 사용자 회원가입 API 시작
app.post('/api/register', (req: Request, res: Response) => {
  const { id, password, name } = req.body as { id: string; password: string; name: string; };
  console.log("받은 데이터:", { id, password, name });

  // Step 1: 아이디 중복 확인
  db.query('SELECT * FROM user WHERE id = ?', [id])
    .then((rows_id: any) => {
      if (rows_id.length > 0) {
        console.log("아이디가 이미 존재합니다:", id);
        return res.status(400).json({ success: false, message: '아이디가 이미 존재합니다' });
      }

      // Step 2: 비밀번호 암호화
      return bcrypt.hash(password, 10);
    })
    .then((hashedPassword: string) => {
      console.log("Hashed password:", hashedPassword);

      // Step 3: 사용자 저장
      return db.query(
        'INSERT INTO user (id, password, plain_password, name) VALUES (?, ?, ?, ?)',
        [id, hashedPassword, password, name]
      );
    })
    .then((result: any) => {
      console.log("사용자 삽입 결과:", result);
      res.status(201).json({ success: true, message: '사용자가 성공적으로 등록되었습니다' });
    })
    .catch((err: any) => {
      // Step 4: 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({ success: false, message: '서버 오류 발생', error: err.message });
    });
}); // 사용자 회원가입 API 끝





// *** 기존 및 새로운 작업 저장 및 편집 시작
app.post('/api/saveTask', (req: Request, res: Response) => {
  const { id, user_id, title, content, start, end, color } = req.body;

  console.log("작업 저장 요청 데이터:", req.body, "\n\n");

  if (!user_id || !title || !start || !end || !color) {
    res.status(400).json({
      success: false,
      message: "필수 입력값이 누락되었습니다.",
    });
    return;
  }

  if (id && id > 0) {
    // 업데이트 쿼리
    const updateQuery = `
      UPDATE task
      SET title = ?, content = ?, start_date = ?, end_date = ?, color = ?, finished = 0, deleted = 0
      WHERE task_id = ? AND user_id = ?
    `;

    db.query(updateQuery, [
      title,
      content || "",
      new Date(start).toISOString().slice(0, 19).replace("T", " "),
      new Date(end).toISOString().slice(0, 19).replace("T", " "),
      color,
      id,
      user_id,
    ])
      .then((result: any) => {
        if (result.affectedRows > 0) {
          // 업데이트된 데이터 조회 쿼리
          return db.query(`SELECT * FROM task WHERE task_id = ? AND user_id = ?`, [id, user_id]);
        } else {
          res.status(404).json({
            success: false,
            message: "업데이트할 작업을 찾을 수 없습니다.",
          });
          throw new Error("업데이트할 작업 없음");
        }
      })
      .then((rows: any) => {
        if (rows.length > 0) {
          console.log("업데이트된 작업 데이터 및 형식 확인:", rows[0]);

          res.status(200).json({
            success: true,
            message: "작업이 성공적으로 업데이트되었습니다.",
            task: rows[0], // 업데이트된 작업 데이터 반환
          });
        }
      })
      .catch((err: any) => {
        if (err.message !== "업데이트할 작업 없음") {
          console.error("작업 업데이트 중 오류 발생:", err);
          res.status(500).json({
            success: false,
            message: "작업 업데이트 중 서버 오류가 발생했습니다.",
            error: err.message,
          });
        }
      });
  } else {
    // 삽입 쿼리
    const insertQuery = `
      INSERT INTO task (user_id, title, content, start_date, end_date, color, finished, deleted)
      VALUES (?, ?, ?, ?, ?, ?, 0, 0)
    `;

    db.query(insertQuery, [
      user_id,
      title,
      content || "",
      new Date(start).toISOString().slice(0, 19).replace("T", " "),
      new Date(end).toISOString().slice(0, 19).replace("T", " "),
      color,
    ])
      .then((result: any) => {
        console.log("DB 삽입 결과:", result.insertId, typeof result.insertId);

        // 삽입된 데이터 조회 쿼리
        return db.query(`SELECT * FROM task WHERE task_id = ? AND user_id = ?`, [result.insertId, user_id]);
      })
      .then((rows: any) => {
        if (rows.length > 0) {
          console.log("업데이트된 작업 데이터 및 형식 확인:", rows[0]);
          
          res.status(201).json({
            success: true,
            message: "작업이 성공적으로 저장되었습니다.",
            task: rows[0], // 삽입된 작업 데이터 반환
          });
        }
      })
      .catch((err: any) => {
        console.error("작업 저장 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "작업 저장 중 서버 오류가 발생했습니다.",
          error: err.message,
        });
      });
  }
}); // 기존 및 새로운 작업 저장 및 편집 끝



// *** 작업 삭제 API 시작
app.post('/api/deleteTask', (req: Request, res: Response) => {
  const { task_id, user_id } = req.body;

  console.log("작업 삭제 요청 데이터:", req.body);

  // 입력값 검증
  if (!task_id || !user_id) {
    res.status(400).json({
      success: false,
      message: "필수 입력값이 누락되었습니다. (task_id, user_id)",
    });
    return;
  }

  // 삭제 쿼리 (논리 삭제)
  const deleteQuery = `
    UPDATE task
    SET deleted = 1
    WHERE task_id = ? AND user_id = ? AND deleted = 0
  `;

  db.query(deleteQuery, [task_id, user_id])
    .then((result: any) => {
      if (result.affectedRows > 0) {
        // 삭제된 데이터 조회 쿼리
        return db.query(`SELECT * FROM task WHERE task_id = ? AND user_id = ?`, [task_id, user_id]);
      } else {
        res.status(404).json({
          success: false,
          message: "삭제할 작업을 찾을 수 없거나 이미 삭제되었습니다.",
        });
        throw new Error("삭제할 작업 없음");
      }
    })
    .then((rows: any) => {
      if (rows.length > 0) {
        console.log("삭제된 작업 데이터:", rows[0]);  // 개발자가 확인하기 위한 로그

        res.status(200).json({
          success: true,
          message: "작업이 성공적으로 삭제되었습니다.",
          task: rows[0], // 삭제된 작업 데이터 반환
        });
      }
    })
    .catch((err: any) => {
      if (err.message !== "삭제할 작업 없음") {
        console.error("작업 삭제 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "작업 삭제 중 서버 오류가 발생했습니다.",
          error: err.message,
        });
      }
    });
}); // 작업 삭제 API 끝


// *** 작업 완료 API 시작
app.post('/api/finishTask', (req: Request, res: Response) => {
  const { task_id, user_id } = req.body;

  console.log("작업 완료 요청 데이터:", req.body);

  // 입력값 검증
  if (!task_id || !user_id || typeof task_id !== "number" || typeof user_id !== "number") {
    res.status(400).json({
      success: false,
      message: "필수 입력값이 누락되었거나 잘못된 형식입니다. (task_id, user_id는 숫자여야 합니다)",
    });
    return;
  }

  // 완료 쿼리
  const finishQuery = `
    UPDATE task
    SET finished = 1
    WHERE task_id = ? AND user_id = ? AND deleted = 0 AND finished = 0
  `;

  db.query(finishQuery, [task_id, user_id])
    .then((result: any) => {
      if (result.affectedRows > 0) {
        // 완료된 데이터 조회 쿼리
        return db.query(`SELECT * FROM task WHERE task_id = ? AND user_id = ?`, [task_id, user_id]);
      } else {
        res.status(404).json({
          success: false,
          message: "완료할 작업을 찾을 수 없거나 이미 완료되었습니다.",
        });
        throw new Error("완료할 작업 없음");
      }
    })
    .then((rows: any) => {
      if (rows.length > 0) {
        console.log("완료된 작업 데이터:", rows[0]); // 개발자가 확인하기 위한 로그

        res.status(200).json({
          success: true,
          message: "작업이 성공적으로 완료되었습니다.",
          task: rows[0], // 완료된 작업 데이터 반환
        });
      }
    })
    .catch((err: any) => {
      if (err.message !== "완료할 작업 없음") {
        console.error("작업 완료 중 오류 발생:", err);
        res.status(500).json({
          success: false,
          message: "작업 완료 중 서버 오류가 발생했습니다.",
          error: err.message,
        });
      }
    });
});
// 작업 완료 API 끝

