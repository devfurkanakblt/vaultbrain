import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/newsreader";
import "@fontsource-variable/ibm-plex-sans";
import "@fontsource/ibm-plex-mono/400.css";
import "./styles.css";
import { App } from "./App";
import { applyTheme, loadTheme } from "./theme";

applyTheme(loadTheme());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
