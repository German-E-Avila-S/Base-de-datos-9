const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const upload = multer({ dest: 'uploads/' });
const app = express();
require('dotenv').config();
// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
      if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
          next();
    } else {
      const html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Acceso Denegado</title>
        </head>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 100px;">
          <h1 style="color:red;">Acceso denegado</h1>
          <p>No tienes permisos para acceder a esta sección.</p>
          <button style="padding:10px 20px; background-color:#007BFF; color:white; border:none; border-radius:5px; cursor:pointer;"
            onclick="window.location.href='/'">Volver al inicio</button>
        </body>
        </html>
      `;
      res.status(403).send(html);
    }
  };
}

// Ruta para la página principal
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Servir archivos estáticos (HTML)
app.use(express.static(path.join(__dirname, 'public')));

// Configurar conexión a MySQL
const connection = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASSWORD,   // Contraseña desde .env
  database: process.env.DB_NAME,    // Nombre de la base de datos desde .env
  timezone: 'America/Tijuana'
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

app.use(bodyParser.urlencoded({ extended: true }));

// Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));

app.get('/menu', (req, res) => {
  const menuItems = [
    { nombre: 'Inicio', url: '/index.html' },
    { nombre: 'Equipos', url: '/equipos.html' },
    { nombre: 'Usuarios', url: '/usuarios.html' },
    { nombre: 'Búsqueda', url: '/busqueda.html' }
  ];
  res.json(menuItems);
});

// Ruta para buscar usuarios (devuelve JSON) - devuelve id también
app.get('/buscar', requireLogin, requireRole('admin'), (req, res) => {
  const query = req.query.query || '';
  const sql = `
    SELECT id, nombre_usuario, tipo_usuario
    FROM usuarios
    WHERE nombre_usuario LIKE ?
  `;
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Error en la consulta' });
    }
    res.json(results);
  });
});

// Registro de usuario
app.post('/registrar', (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;

  // Verificar si el nombre de usuario ya existe
  const checkUser = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  connection.query(checkUser, [nombre_usuario], (err, results) => {
    if (err) {
      console.error(err);
      return res.send('Error al verificar usuario existente');
    }

    if (results.length > 0) {
      // Si ya existe, mostrar mensaje o redirigir con error
      return res.send('El nombre de usuario ya está en uso');
    }

    // Verificar código de acceso si el usuario no existe
    const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
    connection.query(query, [codigo_acceso], (err, results) => {
      if (err || results.length === 0) {
        return res.send('Código de acceso inválido');
      }

      const tipo_usuario = results[0].tipo_usuario;
      const hashedPassword = bcrypt.hashSync(password, 10);

      // Insertar nuevo usuario
      const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
      connection.query(insertUser, [nombre_usuario, hashedPassword, tipo_usuario], (err) => {
        if (err) {
          console.error(err);
          return res.send('Error al registrar usuario');
        }
        res.redirect('/login.html');
      });
    });
  });
});

// Ruta para eliminar un usuario
app.post('/eliminar-usuario', requireLogin, requireRole('admin'), (req, res) => {
  const { id } = req.body;

  // Validar ID
  if (!id || isNaN(id)) {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body style="text-align:center; font-family: Arial; margin-top: 100px;">
        <h1 style="color:red;">Error: ID del usuario inválido.</h1>
        <button onclick="window.location.href='/'">Volver a la página principal</button>
      </body>
      </html>
    `;
    return res.send(html);
  }

  const query = 'DELETE FROM usuarios WHERE id = ?';
  connection.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error al eliminar usuario:', err);
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/styles.css"></head>
        <body style="text-align:center; font-family: Arial; margin-top:100px;">
          <h1 style="color:red;">Error al eliminar el usuario de la base de datos.</h1>
          <button onclick="window.location.href='/'">Volver a la página principal</button>
        </body>
        </html>
      `);
    }

    if (result.affectedRows === 0) {
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/styles.css"></head>
        <body style="text-align:center; font-family: Arial; margin-top:100px;">
          <h1 style="color:red;">No se encontró ningún usuario con ID ${id}.</h1>
          <button onclick="window.location.href='/'">Volver a la página principal</button>
          <button onclick="window.location.href='/ver-usuarios'">Ver usuarios</button>
        </body>
        </html>
      `);
    }

    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Usuario Eliminado</title>
      </head>
      <body style="text-align:center; font-family: Arial; margin-top:100px;">
        <h1 style="color:green;">Usuario con ID ${id} eliminado exitosamente.</h1>
        <button onclick="window.location.href='/'">Volver a la página principal</button>
        <button onclick="window.location.href='/ver-usuarios'">Ver usuarios</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

// Ruta para editar un usuario
app.post('/editar-usuario', requireLogin, requireRole('admin'), (req, res) => {
  const { id, nombre_usuario, tipo_usuario } = req.body;

  if (!id || isNaN(id) || !nombre_usuario || !tipo_usuario) {
    const html = `
      <html>
      <head><link rel="stylesheet" href="/styles.css"></head>
      <body style="text-align:center; font-family: Arial; margin-top: 100px;">
        <h1 style="color:red;">Error: Datos inválidos para editar el usuario.</h1>
        <button onclick="window.location.href='/'">Volver a la página principal</button>
      </body>
      </html>
    `;
    return res.send(html);
  }

  const query = 'UPDATE usuarios SET nombre_usuario = ?, tipo_usuario = ? WHERE id = ?';
  connection.query(query, [nombre_usuario, tipo_usuario, id], (err, result) => {
    if (err) {
      console.error('Error al editar usuario:', err);
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/styles.css"></head>
        <body style="text-align:center; font-family: Arial; margin-top:100px;">
          <h1 style="color:red;">Error al actualizar el usuario.</h1>
          <button onclick="window.location.href='/'">Volver a la página principal</button>
        </body>
        </html>
      `);
    }

    if (result.affectedRows === 0) {
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/styles.css"></head>
        <body style="text-align:center; font-family: Arial; margin-top:100px;">
          <h1 style="color:red;">No se encontró ningún usuario con ID ${id}.</h1>
          <button onclick="window.location.href='/'">Volver a la página principal</button>
          <button onclick="window.location.href='/ver-usuarios'">Ver usuarios</button>
        </body>
        </html>
      `);
    }

    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Usuario Editado</title>
      </head>
      <body style="text-align:center; font-family: Arial; margin-top:100px;">
        <h1 style="color:green;">Usuario con ID ${id} actualizado correctamente.</h1>
        <button onclick="window.location.href='/'">Volver a la página principal</button>
        <button onclick="window.location.href='/ver-usuarios'">Ver usuarios</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

// Ruta para el excel
app.post('/upload', upload.single('excelFile'), (req, res) => {
  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  data.forEach(row => {
    const { nombre, descripcion } = row;
    const sql = `INSERT INTO equipo (nombre, descripcion) VALUES (?, ?)`;
    connection.query(sql, [nombre, descripcion], err => {
      if (err) throw err;
    });
  });

  res.send('<h1>Archivo cargado y datos guardados</h1><a href="/equipos.html">Volver</a>');
});

// Ruta para insertar un nuevo equipo
app.post('/insertar-equipo', requireLogin, requireRole('admin'), (req, res) => {
  const { nombre, descripcion } = req.body;

  if (!nombre || !descripcion || nombre.trim() === '' || descripcion.trim() === '') {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body style="font-family: Arial; text-align: center; margin-top: 100px;">
        <h1 style="color:red;">Error: todos los campos son obligatorios.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  }

  const query = 'INSERT INTO equipo (nombre, descripcion) VALUES (?, ?)';
  connection.query(query, [nombre, descripcion], (err, result) => {
    if (err) {
      console.error(err);
      return res.send('Error al guardar el equipo en la base de datos.');
    }

    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Equipo Guardado</title>
      </head>
      <body style="font-family: Arial; text-align: center; margin-top: 100px;">
        <h1>Equipo "${nombre}" guardado correctamente.</h1>
        <button onclick="window.location.href='/'">Volver</button>
        <button onclick="window.location.href='/equipos'">Ver Equipos</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

//Ruta para la decarga
app.get('/download', requireLogin, requireRole('admin'), (req, res) => {
  const sql = `SELECT * FROM equipo`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Equipos');

    const filePath = path.join(__dirname, 'uploads', 'equipos.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'equipos.xlsx');
  });
});

// Ruta para guardar insumos en la base de datos
  app.post('/add-insumo', requireLogin, requireRole('admin','medico'), (req, res) => {
    const { nombre, cantidad, proveedor, fecha, departamento_id } = req.body;
    if (!nombre || !cantidad || !proveedor || nombre.trim() === '' || isNaN(cantidad) || proveedor.trim() === ''|| isNaN(departamento_id))  {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1 style="color:red;">Error: todos los campos son obligatorios.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  }
    const query = 'INSERT INTO insumos (nombre, cantidad, proveedor, fecha_adquisicion, departamento_id) VALUES (?, ?, ?, ?,?)';

    db.query(query, [nombre, cantidad, proveedor, fecha, departamento_id], (err, result) => {
      if (err) {
        console.error('Error insertando datos:', err);
        return res.status(500).send('Error al registrar el insumo');
      }
      const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente Guardado</title>
      </head>
      <body>
        <h1>Insumo ${nombre} guardado en la base de datos.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
      res.send(html);
    });
  });

// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  connection.query('SELECT * FROM usuarios WHERE nombre_usuario = ?', 
    [nombre_usuario], async (err, results) => {
    if (err || results.length === 0) {
      const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1 style="color:red;">Error: Usuario no encontrado.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
      return res.send(html);
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (match) {
        req.session.user = {
            id: user.id,
            username: user.nombre_usuario,
            tipo_usuario: user.tipo_usuario // Aquí se establece el tipo de usuario en la sesión
        };
         // Redirigir al usuario a la página principal
        res.redirect('/');
    } else {
      const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1 style="color:red;">Error: Contraseña incorrecta.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
      res.send(html);
    }
  });
});

// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
    res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Ruta protegida (Página principal después de iniciar sesión)
app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Ruta para buscar pacientes según filtros
app.get('/buscar-pacientes', requireLogin, requireRole('admin','medico'), (req, res) => {
  const { name_search, age_search } = req.query;
  let query = 'SELECT * FROM pacientes WHERE 1=1';

  if (name_search) {
    query += ` AND nombre LIKE '%${name_search}%'`;
  }
  if (age_search) {
    query += ` AND edad = ${age_search}`;
  }

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de Búsqueda</title>
      </head>
      <body>
        <h1>Resultados de Búsqueda</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para ordenar pacientes por frecuencia cardiaca
app.get('/ordenar-pacientes', requireLogin, requireRole('admin','medico'), (req, res) => {
  console.log('ordenando pacienctes')
  const query = 'SELECT * FROM pacientes ORDER BY frecuencia_cardiaca DESC';

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Pacientes Ordenados</title>
      </head>
      <body>
        <h1>Pacientes Ordenados por Frecuencia Cardiaca</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para Ver a los pacientes
app.get('/pacientes', requireLogin, requireRole('admin','medico'), (req, res) => {
  connection.query('SELECT * FROM pacientes', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Pacientes</title>
      </head>
      <body>
        <h1>Pacientes Registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Id</th>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Frecuencia Cardiaca (bpm)</th>
              <th>Accion</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.id}</td>
          <td>${paciente.nombre}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.frecuencia_cardiaca}</td>
          <td>
            <form action="/eliminar-paciente" method="POST" style="margin:0;" onsubmit="return validarCheckbox(${paciente.id})">
              <input type="hidden" name="id" value="${paciente.id}">
              <label style="margin-right:5px;">
                <input type="checkbox" id="check-${paciente.id}"> Confirmar
              </label>
              <button type="submit" style="background:red; color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;">
                Eliminar Paciente
              </button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver a la pagina principal</button>

        <script>
          function validarCheckbox(id) {
            const checkbox = document.getElementById('check-' + id);
            if (!checkbox.checked) {
              alert('Debes marcar la casilla de confirmación antes de eliminar.');
              return false; // evita que se envíe el formulario
            }
            return confirm('¿Estás seguro de que deseas eliminar este paciente?');
          }
        </script>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para mostrar los MEDICOS de la base de datos en formato HTML
app.get('/medicos', requireLogin, requireRole('admin'), (req, res) => {
  connection.query('SELECT * FROM medicos', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Médicos</title>

        <!-- Bootstrap -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

      </head>
      <body class="bg-light">

        <div class="container py-5">

          <h1 class="text-center mb-4">Médicos Registrados</h1>

          <div class="table-responsive shadow-sm">
            <table class="table table-hover table-bordered text-center align-middle bg-white">
              <thead class="table-dark">
                <tr>
                  <th>Nombre</th>
                  <th>Especialidad</th>
                </tr>
              </thead>
              <tbody>
    `;

    results.forEach(medico => {
      html += `
        <tr>
          <td>${medico.nombre}</td>
          <td>${medico.especialidad}</td>
        </tr>
      `;
    });

    html += `
              </tbody>
            </table>
          </div>

          <div class="text-center mt-4">
            <button onclick="window.location.href='/'" class="btn btn-secondary px-4">
              Volver
            </button>
          </div>

        </div>

        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

      </body>
      </html>
    `;

    res.send(html);
  });
});


// Ruta para insertar un nuevo médico
app.post('/insertar-medico', requireLogin, requireRole('admin'), (req, res) => {
  const { medico_name, especialidad } = req.body;
  if (!medico_name || !especialidad || medico_name.trim() === '' || especialidad.trim() === '') {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1 style="color:red;">Error: todos los campos son obligatorios.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  }
  const query = 'INSERT INTO medicos (nombre, especialidad) VALUES (?, ?)';
  connection.query(query, [medico_name, especialidad], (err, result) => {
    if (err) {
      return res.send('Error al insertar el médico.');
    }
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Medico</title>
      </head>
      <body>
        <h1>Medico ${medico_name} guardado en la base de datos.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);


  });
});

// Ruta para guardar datos en la base de datos
app.post('/submit-data', requireLogin, requireRole('admin','medico'), (req, res) => {
  const { name, age, heart_rate } = req.body;
   if (!name || !age || !heart_rate || name.trim() === '' || isNaN(age) || isNaN(heart_rate)) {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body>
        <h1 style="color:red;">Error: todos los campos son obligatorios.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    return res.send(html);
  }
  const query = 'INSERT INTO pacientes (nombre, edad, frecuencia_cardiaca) VALUES (?, ?, ?)';
  connection.query(query, [name, age, heart_rate], (err, result) => {
    if (err) {
      return res.send('Error al guardar los datos en la base de datos.');
    }

    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente Guardado</title>
      </head>
      <body>
        <h1>Paciente ${name} guardado en la base de datos.</h1>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

// Ruta para eliminar un paciente
app.post('/eliminar-paciente', requireLogin, requireRole('admin','medico'), (req, res) => {
  const { id } = req.body;

  if (!id || isNaN(id)) {
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
      </head>
      <body style="text-align:center; font-family: Arial; margin-top: 100px;">
        <h1 style="color:red;">Error: ID del paciente inválido.</h1>
        <button onclick="window.location.href='/'">Volver a la pagina principal</button>
      </body>
      </html>
    `;
    return res.send(html);
  }
  const query = 'DELETE FROM pacientes WHERE id = ?';
  connection.query(query, [id], (err, result) => {
    if (err) {
      return res.send('Error al eliminar el paciente de la base de datos.');
    }

    if (result.affectedRows === 0) {
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/styles.css"></head>
        <body style="text-align:center; font-family: Arial; margin-top:100px;">
          <h1 style="color:red;">No se encontró ningún paciente con ID ${id}.</h1>
          <button onclick="window.location.href='/'">Volver a la pagina principal</button>
          <button onclick="window.location.href='/pacientes'">Ver pacientes</button>
        </body>
        </html>
      `);
    }

    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Paciente Eliminado</title>
      </head>
      <body style="text-align:center; font-family: Arial; margin-top:100px;">
        <h1 style="color:green;">Paciente con ID ${id} eliminado exitosamente.</h1>
          <button onclick="window.location.href='/'">Volver a la pagina principal</button>
          <button onclick="window.location.href='/pacientes'">Ver pacientes</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

// Ruta para que solo admin pueda ver todos los usuarios
app.get('/ver-usuarios', requireLogin, requireRole('admin'), (req, res) => {
  connection.query('SELECT * FROM usuarios', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Usuarios Registrados</title>

        <!-- Bootstrap -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>

      <body class="bg-light">

        <div class="container py-5">

          <h1 class="text-center mb-4">Usuarios Registrados</h1>

          <div class="card shadow-sm">
            <div class="card-body">

              <table class="table table-striped table-hover">
                <thead class="table-dark">
                  <tr>
                    <th>Nombre</th>
                    <th>Tipo de usuario</th>
                  </tr>
                </thead>
                <tbody>
    `;

    results.forEach(usuario => {
      html += `
        <tr>
          <td>${usuario.nombre_usuario}</td>
          <td>${usuario.tipo_usuario}</td>
        </tr>
      `;
    });

    html += `
                </tbody>
              </table>

              <div class="text-center mt-3">
                <a href="/" class="btn btn-primary">Volver</a>
              </div>

            </div>
          </div>

        </div>

        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

      </body>
      </html>
    `;

    res.send(html);
  });
});


// Ruta para que el usuario vea sus datos
app.get('/mis-datos', requireLogin, (req, res) => {
  const userId = req.session.user.id;

  const query = 'SELECT nombre_usuario, tipo_usuario FROM usuarios WHERE id = ?';
  connection.query(query, [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.send('Error al obtener tus datos.');
    }

    const usuario = results[0];

    const html = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />

        <title>Mis Datos</title>

        <!-- Bootstrap -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>

      <body class="bg-light">

        <div class="container py-5">
          <h1 class="text-center mb-4">Mis Datos</h1>

          <div class="card shadow-sm mx-auto" style="max-width: 500px;">
            <div class="card-body">

              <table class="table table-bordered mb-3">
                <tr>
                  <th class="table-dark">Nombre de usuario</th>
                  <td>${usuario.nombre_usuario}</td>
                </tr>
                <tr>
                  <th class="table-dark">Tipo de usuario</th>
                  <td>${usuario.tipo_usuario}</td>
                </tr>
              </table>

              <div class="text-center">
                <a href="/" class="btn btn-primary">
                  Volver
                </a>
              </div>

            </div>
          </div>
        </div>

        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

      </body>
      </html>
    `;

    res.send(html);
  });
});


// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
}); 
