import { createSignal, For } from "solid-js";

function Fun() {
  return (
    <>
      <span class="ms-4 rounded-full border-4 border-red-500 bg-red-300 px-4 py-2 font-serif font-black text-red-900">
        Monday
      </span>
      <span class="ms-4 rounded-full border-4 border-orange-500 bg-orange-300 px-4 py-2 font-serif font-black text-orange-900">
        Tuesday
      </span>
      <span class="ms-4 rounded-full border-4 border-yellow-500 bg-yellow-300 px-4 py-2 font-serif font-black text-yellow-900">
        Wednesday
      </span>
      <span class="ms-4 rounded-full border-4 border-green-500 bg-green-300 px-4 py-2 font-serif font-black text-green-900">
        Thursday
      </span>
      <span class="ms-4 rounded-full border-4 border-blue-500 bg-blue-300 px-4 py-2 font-serif font-black text-blue-900">
        Friday
      </span>
      <span class="ms-4 rounded-full border-4 border-indigo-500 bg-indigo-300 px-4 py-2 font-serif font-black text-indigo-900">
        Saturday
      </span>
      <span class="ms-4 rounded-full border-4 border-violet-500 bg-violet-300 px-4 py-2 font-serif font-black text-violet-900">
        Sunday
      </span>
    </>
  );
}

type Entry = [from: string, to: string];
type Data = {
  date: string;
  entries: Entry[];
};
function App() {
  const [data] = createSignal<Data[]>([
    {
      date: "2026-04-27",
      entries: [
        ["14:00", "14:40"],
        ["16:30", "20:30"],
      ],
    },
    {
      date: "2026-04-28",
      entries: [
        ["10:20", "11:30"],
        ["14:30", "18:00"],
        ["18:15", "19:45"],
      ],
    },
    {
      date: "2026-04-29",
      entries: [
        ["13:00", "13:30"],
        ["14:30", "19:40"],
      ],
    },
    {
      date: "2026-04-30",
      entries: [["09:15", "13:00"]],
    },
    {
      date: "2026-05-01",
      entries: [
        ["10:45", "11:15"],
        ["17:00", "18:00"],
      ],
    },
    { date: "2026-05-02", entries: [["10:15", "18:30"]] },
    { date: "2026-05-03", entries: [] },
  ]);
  return (
    <>
      <h1>Time</h1>
      <aside>
        <nav>
          <ul>
            <li>
              <a href="#">Home</a>
            </li>
            <li>
              <a href="#">About</a>
            </li>
            <li>
              <a href="#">Contact</a>
            </li>
          </ul>
        </nav>
      </aside>
      <main class="grid grid-cols-[auto_1fr] gap-4">
        <For each={data()}>
          {(item) => {
            // const dayOfWeek = item?.date.toLocaleString(undefined, {
            //   weekday: "long",
            // });

            const date = Temporal.PlainDate.from(item.date);
            const weekday = date.toLocaleString(undefined, {
              weekday: "long",
            });

            return (
              <article
                data-day={date.dayOfWeek}
                class="col-span-full grid grid-cols-subgrid grid-rows-(--grid-rows) gap-4 rounded-4xl p-4 [corner-shape:squircle] data-[day=1]:bg-red-500 data-[day=2]:bg-orange-500 data-[day=3]:bg-yellow-500 data-[day=4]:bg-green-500 data-[day=5]:bg-blue-500 data-[day=6]:bg-indigo-500 data-[day=7]:bg-violet-500"
                style={{
                  // `grid-row: 1 / -1;` (`row-span-full`) does not work without a known row length
                  "--grid-rows": `repeat(${item.entries.length}, minmax(0, 1fr))`,
                }}
              >
                <time class="row-span-full block">
                  <span>{weekday}</span>
                  <span class="block">{date.toLocaleString(undefined, { day: "2-digit" })}</span>
                </time>
                <For each={item.entries}>
                  {([from, to]) => {
                    const fromTime = Temporal.PlainTime.from(from);
                    const toTime = Temporal.PlainTime.from(to);

                    const duration = toTime.since(fromTime);
                    return (
                      <section class="col-start-2">
                        <input type="time" value={from} step="900" />
                        <input type="time" value={to} step="900" />
                        <time>
                          {duration.toLocaleString(undefined, {
                            style: "digital",
                            hours: "2-digit",
                            secondsDisplay: "auto",
                          })}
                        </time>
                      </section>
                    );
                  }}
                </For>
              </article>
            );
          }}
        </For>
        {/* <article class="rounded-2xl bg-orange-500">
          <time>April 28, 2026</time>
        </article>
        <article class="rounded-2xl bg-yellow-500">
          <time>April 29, 2026</time>
        </article>
        <article class="rounded-2xl bg-green-500">
          <time>April 30, 2026</time>
        </article>
        <article class="rounded-2xl bg-blue-500">
          <time>May 1, 2026</time>
        </article>
        <article class="rounded-2xl bg-indigo-500">
          <time>May 2, 2026</time>
        </article>
        <article class="rounded-2xl bg-violet-500">
          <time>May 3, 2026</time>
        </article> */}
      </main>
    </>
  );
}

export default App;
