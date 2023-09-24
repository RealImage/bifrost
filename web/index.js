import { Elm } from './src/Main.elm';
import { createKeyAndCSR } from './src/crypto';

const app = Elm.Main.init();

app.ports.generate.subscribe(async(req) => {
  let res
  try {
    res = await createKeyAndCSR(req);
  } catch ({ message }) {
    res = { error: message };
  }
  app.ports.receive.send(res);
});