const sharp = require('../node_modules/sharp');
const path = require('path');

async function removeDarkBackground() {
  const inputPath = path.join(__dirname, '../public/assets/hangar-emblem.png');
  const outputPath = path.join(__dirname, '../public/assets/hangar-emblem-nobg.png');

  const { data, info } = await sharp(inputPath)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const { width, height } = info;
  const ch = 4; // RGBA
  const out = Buffer.from(data);

  for (let i = 0; i < out.length; i += ch) {
    const r = out[i];
    const g = out[i + 1];
    const b = out[i + 2];

    // Luminance (perceived brightness)
    const lum = 0.299 * r + 0.587 * g + 0.114 * b;

    // The dark navy background is:  low luminance + blue-dominant
    // Logo elements (gold, silver highlights) have much higher luminance
    const darkThresholdLow  = 16;  // below this → fully transparent
    const darkThresholdHigh = 44;  // above this → fully opaque
    const isBluish = b >= r - 4 && b >= g - 4; // navy-ish hue

    if (lum < darkThresholdLow) {
      out[i + 3] = 0;
    } else if (lum < darkThresholdHigh && isBluish) {
      // Smooth quadratic fade in the transition zone
      const t = (lum - darkThresholdLow) / (darkThresholdHigh - darkThresholdLow);
      out[i + 3] = Math.round(t * t * 255);
    }
    // Otherwise: keep fully opaque (gold, silver, bright elements)
  }

  await sharp(out, { raw: { width, height, channels: ch } })
    .png({ compressionLevel: 9 })
    .toFile(outputPath);

  console.log(`Done → ${outputPath}`);
  console.log(`Dimensions: ${width} × ${height}`);
}

removeDarkBackground().catch(err => { console.error(err); process.exit(1); });
