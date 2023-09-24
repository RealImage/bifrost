import { Elm } from './src/Main.elm';
import { createKeyAndCSR } from './src/crypto';

const app = Elm.Main.init();

app.ports.generate.subscribe(async(req) => {
  console.log(req);
  const key = req.key ? req.key : null;
  const res = await createKeyAndCSR(req.namespace, key);
  console.log(res);
  app.ports.receive.send(res);
});