/* @refresh reload */
import { render } from 'solid-js/web'
import './index.css'
import App from './App.tsx'

// If I am not mistaken, this should keep the polyfill out of the bundle
if (!("Temporal" in globalThis)) {
    console.debug("Temporal not found, polyfilling...");
    const { Temporal } = await import("temporal-polyfill");
    // @ts-expect-error
    globalThis.Temporal = Temporal;
}

render(() => <App />, document.body)
