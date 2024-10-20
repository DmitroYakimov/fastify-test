const fastify = require('fastify')({ logger: true });
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const fastifyAuth = require('@fastify/auth');
const fastifyBasicAuth = require('@fastify/basic-auth');
const fastifyMultipart = require('@fastify/multipart');
const mime = require('mime-types');

const { pipeline } = require('stream');
const { promisify } = require('util');
const pump = promisify(pipeline);

const start = async () => {
  try {
    await fastify.register(require('@fastify/postgres'), {
      connectionString: 'postgres://postgres:1234@localhost/chat'
    });


    await fastify.register(fastifyBasicAuth, {
      validate,
      authenticate: true
    });

    await fastify.register(fastifyAuth);

    await fastify.register(fastifyMultipart);

    await fastify.register(require('@fastify/formbody'));

    async function validate(username, password, req, reply) {
      const client = await fastify.pg.connect();
      const { rows } = await client.query('SELECT * FROM users WHERE username=$1', [username]);

      if (rows.length === 0) {
        client.release();
        return new Error('User not found');
      }

      const user = rows[0];
      const match = await bcrypt.compare(password, user.password_hash);

      if (!match) {
        client.release();
        return new Error('Invalid credentials');
      }

      client.release();
    }

    fastify.post('/account/register', async (req, reply) => {
      const { username, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const client = await fastify.pg.connect();

      try {
        await client.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hashedPassword]);
        reply.code(201).send({ message: 'User registered' });
      } catch (err) {
        reply.code(500).send({ error: 'Error registering user' });
      } finally {
        client.release();
      }
    });

    fastify.post('/message/text', { preHandler: fastify.auth([fastify.basicAuth]) }, async (req, reply) => {
      const { content } = req.body; 
    
      console.log('Received content:', content);
    
      if (!content) {
        return reply.code(400).send({ error: 'Content is required' });
      }
    
      const client = await fastify.pg.connect();
      try {
        await client.query('INSERT INTO messages (content, type) VALUES ($1, $2)', [content, 'text']);
        reply.code(201).send({ message: 'Text message created' });
      } catch (err) {
        console.error(err);
        reply.code(500).send({ error: 'Error saving message' });
      } finally {
        client.release();
      }
    });


    fastify.post('/message/file', { preHandler: fastify.auth([fastify.basicAuth]) }, async (req, reply) => {
      const client = await fastify.pg.connect();

      
      const data = await req.file(); 
      const filePath = path.join(__dirname, 'uploads', data.filename);

      await pump(data.file, fs.createWriteStream(filePath));
      try {
        await client.query('INSERT INTO messages (content, type) VALUES ($1, $2)', [filePath, 'file']);
        reply.code(201).send({ message: 'File message posted' });
      } catch (err) {
        reply.code(500).send({ error: 'Error posting file message' });
      } finally {
        client.release();
      }
    });

    fastify.get('/message/list', { preHandler: fastify.auth([fastify.basicAuth]) }, async (req, reply) => {
      const { page = 1, limit = 10 } = req.query;
      const offset = (page - 1) * limit;
      const client = await fastify.pg.connect();

      try {
        const { rows } = await client.query('SELECT * FROM messages ORDER BY id DESC LIMIT $1 OFFSET $2', [limit, offset]);
        reply.send(rows);
      } catch (err) {
        reply.code(500).send({ error: 'Error fetching messages' });
      } finally {
        client.release();
      }
    });

    fastify.get('/message/content', { preHandler: fastify.auth([fastify.basicAuth]) }, async (req, reply) => {
      const { id } = req.query;
      const client = await fastify.pg.connect();

      try {
        const { rows } = await client.query('SELECT * FROM messages WHERE id=$1', [id]);

        if (rows.length === 0) {
          return reply.code(404).send({ error: 'Message not found' });
        }

        const message = rows[0];
        if (message.type === 'text') {
          reply.type('text/plain').send(message.content);
        } else if (message.type === 'file') {
          const filePath = message.content; 

      if (!fs.existsSync(filePath)) {
        reply.code(404).send({ error: 'File not found' });
        return;
      }

      const mimeType = mime.lookup(filePath) || 'application/octet-stream';

      const fileContent = fs.readFileSync(filePath); 

      reply.type(mimeType).send(fileContent); 
        }
      } catch (err) {
        console.error(err);
        reply.code(500).send({ error: 'Error fetching message content' });
      } finally {
        client.release();
      }
    });

    await fastify.listen({ port: 3000 });
    console.log('Server listening on http://localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();