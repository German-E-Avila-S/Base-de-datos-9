
CREATE DATABASE IF NOT EXISTS proyecto CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'proyecto'@'localhost' IDENTIFIED BY 'proyecto_pass';
GRANT ALL PRIVILEGES ON proyecto.* TO 'proyecto'@'localhost';
FLUSH PRIVILEGES;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre_usuario VARCHAR(50) UNIQUE NOT NULL,
    contraseña VARCHAR(255) NOT NULL,
    tipo_usuario ENUM('admin','recepcionista','laboratorista') NOT NULL
);

mysql> CREATE TABLE pacientes (
    ->     id INT AUTO_INCREMENT PRIMARY KEY,
    ->     nombre VARCHAR(120) NOT NULL,
    ->     apellido VARCHAR(120) NOT NULL,
    ->     fecha_nacimiento DATE NOT NULL,
    ->     sexo ENUM('M','F','Otro') NOT NULL
    -> );

mysql> CREATE TABLE medicos (
         id INT AUTO_INCREMENT PRIMARY KEY,
         nombre VARCHAR(120) NOT NULL,
         apellido VARCHAR(120) NOT NULL,
         especialidad VARCHAR(100),
         correo VARCHAR(120)
     );

mysql> CREATE TABLE citas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        paciente_id INT NOT NULL,
        fecha_cita DATETIME NOT NULL,
        motivo VARCHAR(200),
        estado ENUM('pendiente','completada','cancelada') DEFAULT 'pendiente',
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (paciente_id) REFERENCES pacientes(id)
    );


 CREATE TABLE resultados (
         id INT AUTO_INCREMENT PRIMARY KEY,
         paciente_id INT NOT NULL,
         cita_id INT NOT NULL,
         tipo_estudio VARCHAR(150) NOT NULL,
         valores TEXT NOT NULL,
         laboratorista INT NOT NULL,
         fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
         FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
         FOREIGN KEY (cita_id) REFERENCES citas(id),
         FOREIGN KEY (laboratorista) REFERENCES usuarios(id)
    );

