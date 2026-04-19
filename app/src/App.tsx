function App() {
  const durations = [
    Temporal.Duration.from({ minutes: 40 }),
    Temporal.Duration.from({ hours: 4 }),
    Temporal.Duration.from({ hours: 1, minutes: 10 }),
    Temporal.Duration.from({ hours: 3, minutes: 30 }),
    Temporal.Duration.from({ hours: 1, minutes: 30 }),
    Temporal.Duration.from({ hours: 0, minutes: 30 }),
    Temporal.Duration.from({ hours: 5, minutes: 10 }),
    Temporal.Duration.from({ hours: 3, minutes: 45 }),
    Temporal.Duration.from({ hours: 0, minutes: 30 }),
    Temporal.Duration.from({ hours: 1, minutes: 0 }),
    Temporal.Duration.from({ hours: 8, minutes: 15 }),
  ];
  return (
    <>
      <p>
        Duration{" "}
        {durations
          .reduce(
            (previous, current) => previous.add(current),
            new Temporal.Duration(),
          )
          .toString()}
      </p>
    </>
  );
}

export default App;
