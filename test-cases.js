const { sha256 } = require("js-sha256");

function GetHash(input, salt) {
  const hash = sha256.array(input);

  const combined = Buffer.from([...salt, ...hash]);

  const final = sha256(combined);

  return final;
}

const res = [
  ["testsub", "testsalt"],
  ["testsub1", "testsalt1"],
  [
    "234828807392435446358056555497880649149024438810221282780179882484781739477832841844593114172287969280457406335703338142911137974071300983409127789609798199193439720252695146173774313272223702454068684104558201570357798222868184006489304097010847969324467",
    "852578931364788018513185982358659714401173864637907841920270394435227982857031727727325064752009114825701949779851884942185285061282488020306831906839931346926060221794768416270004097131480282673996138968207616758995359862635952099705647177322643398727502",
  ],
].map(([input, salt]) => {
  const bufferInput = Buffer.from(input, "utf-8");
  const bufferSalt = Buffer.from(salt, "utf-8");

  const test = {
    input: input,
    salt: salt,
    inputBuffer: bufferInput.toString("hex"),
    saltBuffer: bufferSalt.toString("hex"),
    result: GetHash(bufferInput, bufferSalt).toString("hex"),
  };

  return test;
});

console.log(res);
