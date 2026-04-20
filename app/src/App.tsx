import { createMemo, For, Show } from "solid-js";
import { createStore } from "solid-js/store";

function App() {
  const [store, setStore] = createStore<
    [start: Temporal.PlainDateTime, end: Temporal.PlainDateTime][]
  >([]);

  function handleSubmit(event: SubmitEvent) {
    event.preventDefault();

    if (!(event.target instanceof HTMLFormElement)) throw new Error("Expected target to be a form");

    const startInput = event.target.elements.namedItem("start");
    if (!(startInput instanceof HTMLInputElement))
      throw new Error("Expected start input to be an input");

    const start = Temporal.PlainDateTime.from(startInput.value);

    if (start === undefined) throw new Error("Expected start to be a valid date");

    const endInput = event.target.elements.namedItem("end");
    if (!(endInput instanceof HTMLInputElement))
      throw new Error("Expected end input to be an input");

    const end = Temporal.PlainDateTime.from(endInput.value);
    if (end === undefined) throw new Error("Expected end to be a valid date");

    setStore(store.length, [start, end]);
  }

  const now = Temporal.Now.plainDateTimeISO();
  const start = now.toString().substring(0, 16);
  const end = now.add({ minutes: 30 }).toString().substring(0, 16);
  const rows = createMemo(() =>
    store.map(([start, end]) => ({
      year: start.toLocaleString(undefined, { year: "numeric" }),
      month: start.toLocaleString(undefined, { month: "short" }),
      week: start.weekOfYear?.toString(),
      day: start.toLocaleString(undefined, { day: "numeric" }),
      dayOfWeek: start.toLocaleString(undefined, { weekday: "long" }),
      start: start.toLocaleString(undefined, { timeStyle: "medium" }),
      end: end.toLocaleString(undefined, { timeStyle: "medium" }),
    })),
  );
  return (
    <>
      <h1>Time</h1>
      <table>
        <thead>
          <tr>
            <th>Month</th>
            <th>Week</th>
            <th>Day</th>
            <th>Start</th>
            <th>End</th>
          </tr>
        </thead>
        <tbody>
          <Show
            when={rows().length > 0}
            fallback={
              <tr>
                <td colSpan="5">No data</td>
              </tr>
            }
          >
            <For each={rows()}>
              {(row) => (
                <tr>
                  <td>{row.year}</td>
                  <td>{row.month}</td>
                  <td>{row.week}</td>
                  <td>
                    {row.dayOfWeek} {row.day}
                  </td>
                  <td>{row.start}</td>
                  <td>{row.end}</td>
                </tr>
              )}
            </For>
          </Show>
        </tbody>
      </table>
      <form onSubmit={handleSubmit}>
        <label for="start">Start </label>
        <input type="datetime-local" id="start" name="start" value={start} />
        <label for="end">End</label>
        <input type="datetime-local" id="end" name="end" value={end} />
        <button type="submit">Save</button>
      </form>
    </>
  );
}

export default App;
