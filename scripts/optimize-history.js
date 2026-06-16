const sharp = require('sharp');
const path = require('path');
const fs = require('fs');
const files = ['history-1903.jpg','history-1927.jpg','history-1958.jpg','history-today.jpg'];
(async()=>{
  for(const f of files){
    const inp = path.join(__dirname,'../public/assets',f);
    const tmp = inp + '.tmp.jpg';
    const orig = fs.statSync(inp).size;
    await sharp(inp).resize({width:900,withoutEnlargement:true}).jpeg({quality:78,progressive:true}).toFile(tmp);
    const newSize = fs.statSync(tmp).size;
    fs.renameSync(tmp, inp);
    console.log(`${f}: ${Math.round(orig/1024)}KB → ${Math.round(newSize/1024)}KB`);
  }
})().catch(e=>{console.error(e);process.exit(1)});
