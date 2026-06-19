const sharp = require('sharp');
const path = require('path');

const SRC_DIR = 'C:\\Users\\SANTIAGO\\Downloads\\4 fotos cabina';
const OUT_DIR = path.join(__dirname, '..', 'public', 'assets');

const jobs = [
  { src: 'cabina.jpeg', out: 'sim-cabina.webp' },
  { src: 'Potencias.jpeg', out: 'sim-instrumentos.webp' },
  { src: 'Panel intructor.jpeg', out: 'sim-instructor.webp' },
  { src: 'Vista vuelo.png', out: 'sim-ambiente.webp' },
];

(async () => {
  for (const j of jobs) {
    const inPath = path.join(SRC_DIR, j.src);
    const outPath = path.join(OUT_DIR, j.out);
    await sharp(inPath)
      .resize(1200, 900, { fit: 'cover', position: sharp.strategy.attention })
      .webp({ quality: 82 })
      .toFile(outPath);
    console.log('OK', j.src, '->', j.out);
  }
})().catch(e => { console.error(e); process.exit(1); });
