const DATA = window.TRAINING_DATA;
const STORAGE_KEY = 'soc-trainer-pwa-progress-v1';

const state = {
  view: 'learn',
  selectedChapter: 0,
  quiz: [],
  question: null,
  questionIndex: 0,
  selectedAnswer: null,
  score: 0,
  cardIndex: 0,
  cardVisible: false,
  progress: loadProgress(),
};

function loadProgress() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || { completed: [], best: 0, runs: 0 }; }
  catch { return { completed: [], best: 0, runs: 0 }; }
}

function saveProgress() { localStorage.setItem(STORAGE_KEY, JSON.stringify(state.progress)); }
function $(id) { return document.getElementById(id); }
function shuffle(items) { return [...items].sort(() => Math.random() - 0.5); }
function sample(items, count) { return shuffle(items).slice(0, count); }

function init() {
  renderChapters();
  selectChapter(0);
  renderFlashcard();
  newPrompt();
  renderProgress();
  bindEvents();
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('service-worker.js');
}

function bindEvents() {
  document.querySelectorAll('.nav-btn').forEach(btn => btn.addEventListener('click', () => showView(btn.dataset.view)));
  $('markDoneBtn').addEventListener('click', markChapterDone);
  $('startQuizBtn').addEventListener('click', startQuiz);
  $('submitAnswerBtn').addEventListener('click', submitAnswer);
  $('prevCardBtn').addEventListener('click', () => moveCard(-1));
  $('nextCardBtn').addEventListener('click', () => moveCard(1));
  $('toggleCardBtn').addEventListener('click', toggleCard);
  $('newPromptBtn').addEventListener('click', newPrompt);
  $('resetBtn').addEventListener('click', resetProgress);
}

function showView(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  $(`view-${view}`).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
}

function renderChapters() {
  $('chapterList').innerHTML = '';
  DATA.chapters.forEach((chapter, index) => {
    const done = state.progress.completed.includes(index);
    const btn = document.createElement('button');
    btn.className = 'chapter-item';
    btn.innerHTML = `<strong>${done ? 'DONE' : 'TODO'} ${chapter.title}</strong><small>${chapter.minutes} min</small>`;
    btn.addEventListener('click', () => selectChapter(index));
    $('chapterList').appendChild(btn);
  });
}

function selectChapter(index) {
  state.selectedChapter = index;
  const chapter = DATA.chapters[index];
  document.querySelectorAll('.chapter-item').forEach((el, i) => el.classList.toggle('active', i === index));
  $('chapterTitle').textContent = `${chapter.title} | ${chapter.minutes} min`;
  $('chapterContent').textContent = `${chapter.content.trim()}\n\nPuncte cheie:\n${chapter.key_points.map(p => '- ' + p).join('\n')}`;
}

function markChapterDone() {
  if (!state.progress.completed.includes(state.selectedChapter)) state.progress.completed.push(state.selectedChapter);
  saveProgress();
  renderChapters();
  selectChapter(state.selectedChapter);
  renderProgress();
}

function startQuiz() {
  state.quiz = sample(DATA.quizBank, DATA.quizQuestionCount);
  state.questionIndex = 0;
  state.score = 0;
  nextQuestion();
}

function nextQuestion() {
  state.selectedAnswer = null;
  $('explanation').textContent = '';
  if (state.questionIndex >= state.quiz.length) return finishQuiz();
  const raw = state.quiz[state.questionIndex];
  const answers = shuffle(raw.a.map((text, original) => ({ text, original })));
  state.question = { ...raw, answers };
  $('quizMeta').textContent = `Intrebarea ${state.questionIndex + 1}/${DATA.quizQuestionCount} | Scor ${state.score} | Banca ${DATA.quizBank.length}`;
  $('questionText').textContent = raw.q;
  $('answers').innerHTML = '';
  answers.forEach((answer, idx) => {
    const div = document.createElement('button');
    div.className = 'answer';
    div.textContent = answer.text;
    div.addEventListener('click', () => selectAnswer(idx));
    $('answers').appendChild(div);
  });
}

function selectAnswer(index) {
  state.selectedAnswer = index;
  document.querySelectorAll('.answer').forEach((el, i) => el.classList.toggle('selected', i === index));
}

function submitAnswer() {
  if (!state.question) return startQuiz();
  if (state.selectedAnswer === null) { $('explanation').textContent = 'Alege un raspuns.'; return; }
  const picked = state.question.answers[state.selectedAnswer];
  if (picked.original === state.question.c) {
    state.score += 1;
    $('explanation').textContent = `Corect. ${state.question.e}`;
  } else {
    $('explanation').textContent = `Gresit. Raspuns corect: ${state.question.a[state.question.c]}\n${state.question.e}`;
  }
  state.questionIndex += 1;
  setTimeout(nextQuestion, 950);
}

function finishQuiz() {
  const percent = Math.round((state.score / DATA.quizQuestionCount) * 100);
  state.progress.runs += 1;
  state.progress.best = Math.max(state.progress.best, percent);
  saveProgress();
  renderProgress();
  $('quizMeta').textContent = `Quiz terminat: ${state.score}/${DATA.quizQuestionCount} (${percent}%). Best: ${state.progress.best}%`;
  $('questionText').textContent = 'Reia intrebarile si capitolele unde ai ezitat.';
  $('answers').innerHTML = '';
  $('explanation').textContent = '';
  state.question = null;
}

function renderFlashcard() {
  const card = DATA.flashcards[state.cardIndex];
  $('flashFront').textContent = card.front;
  $('flashBack').textContent = state.cardVisible ? card.back : "Apasa 'Arata'.";
}

function toggleCard() { state.cardVisible = !state.cardVisible; renderFlashcard(); }
function moveCard(delta) { state.cardIndex = (state.cardIndex + delta + DATA.flashcards.length) % DATA.flashcards.length; state.cardVisible = false; renderFlashcard(); }

function newPrompt() {
  const prompt = DATA.interviewPrompts[Math.floor(Math.random() * DATA.interviewPrompts.length)];
  $('promptText').textContent = prompt;
}

function renderProgress() {
  $('completedMetric').textContent = `${state.progress.completed.length}/${DATA.chapters.length}`;
  $('bestMetric').textContent = `${state.progress.best}%`;
  $('runsMetric').textContent = state.progress.runs;
}

function resetProgress() {
  if (!confirm('Resetezi progresul?')) return;
  state.progress = { completed: [], best: 0, runs: 0 };
  saveProgress();
  renderChapters();
  selectChapter(0);
  renderProgress();
}

init();
