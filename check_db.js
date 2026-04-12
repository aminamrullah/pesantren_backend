require('dotenv').config();
const mysql = require('mysql2/promise');

async function checkUsers() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_DATABASE,
        port: process.env.DB_PORT || 3306
    });

    try {
        const [users] = await db.execute('SELECT id, name, email, phone, role FROM users');
        console.log('--- USERS LIST ---');
        console.table(users);
        
        const [teachers] = await db.execute('SELECT * FROM teachers');
        console.log('--- TEACHERS LIST ---');
        console.table(teachers);
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await db.end();
    }
}

checkUsers();
