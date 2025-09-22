// Setup: npm install csv-parse
// Run: node starters/javascript.js

const fs = require("fs");
const { parse } = require("csv-parse/sync");

const CVSS_V1_SCORES = {
  AV: { N: 1.0, L: 0.65, P: 0.4 },
  AC: { L: 0.8, H: 0.6 },
  I: { C: 1.0, H: 0.75, L: 0.5 },
};

const CVSS_V2_SCORES = {
  AV: { N: 1.0, A: 0.646, L: 0.395, P: 0.2 },
  AC: { L: 0.71, M: 0.61, H: 0.35 },
  Au: { N: 0.704, S: 0.56, M: 0.45 },
  I: { C: 1.0, H: 0.75, L: 0.5 },
};

const data = fs.readFileSync("cves.csv", "utf8");
const records = parse(data, { columns: true });
//console.log(CVSS_V1_SCORES['VALUE_1']['Value_2'])
records.forEach(row => {
  let nameArray = row['cvss_vector'].split("/")
    let AV_Score = 10
  nameArray.forEach(item => {
    let parts = item.split(":")
    // console.log("line 28")
    let part1 = CVSS_V1_SCORES[parts[0]]
    // console.log(item)
    
    if (CVSS_V1_SCORES[parts[0]] != undefined) {
      let score_part = CVSS_V1_SCORES[parts[0]][parts[1]] 
      // console.log(score_part)
    AV_Score *= score_part
      // console.log(AV_Score)
      // console.log(name)
    }
  
    
  }
  )
    console.log(AV_Score
  }

);
