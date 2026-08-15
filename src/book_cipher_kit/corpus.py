"""corpus -- books to work with when you have no book.

A book cipher is useless without a shared book, and tests are useless
without realistic books. This module provides both:

* embedded public-domain excerpts (Sun Tzu, Aesop, historic documents)
  that ship with the package,
* a deterministic procedural prose generator for synthetic books of any
  size,
* corpus statistics used by the stats and doctor commands.

Everything here is deterministic: the same seed always yields the same
book, so test runs are reproducible.
"""

from __future__ import annotations

import random
from typing import Sequence

# ---------------------------------------------------------------------------
# Embedded public-domain texts
# ---------------------------------------------------------------------------

SUN_TZU = """Sun Tzu said: The art of war is of vital importance to the State.
It is a matter of life and death, a road either to safety or to ruin.
Hence it is a subject of inquiry which can on no account be neglected.
The art of war is governed by five constant factors, to be taken into account in one's deliberations, when seeking to determine the conditions obtaining in the field.
These are: The Moral Law; Heaven; Earth; The Commander; Method and discipline.
The Moral Law causes the people to be in complete accord with their ruler, so that they will follow him regardless of their lives, undismayed by any danger.
Heaven signifies night and day, cold and heat, times and seasons.
Earth comprises distances, great and small; danger and security; open ground and narrow passes; the chances of life and death.
The Commander stands for the virtues of wisdom, sincerity, benevolence, courage and strictness.
By Method and discipline are to be understood the marshaling of the army in its proper subdivisions, the gradations of rank among the officers, the maintenance of roads by which supplies may reach the army, and the control of military expenditure.
These five heads should be familiar to every general: he who knows them will be victorious; he who knows them not will fail.
Therefore, in your deliberations, when seeking to determine the military conditions, let these be made the basis of a comparison, in this wise:
Which of the two sovereigns is imbued with the Moral law?
Which of the two generals has most ability?
With whom lie the advantages derived from Heaven and Earth?
On which side is discipline most rigorously enforced?
Which army is the stronger?
On which side are officers and men more highly trained?
In which army is there the greater constancy both in reward and punishment?
By means of these seven considerations I can forecast victory or defeat.
The general that hearkens to my counsel and acts upon it, will conquer: let such a one be retained in command!
The general that hearkens not to my counsel nor acts upon it, will suffer defeat: let such a one be dismissed!
While heeding the profit of my counsel, avail yourself also of any helpful circumstances over and beyond the ordinary rules.
According as circumstances are favorable, one should modify one's plans.
All warfare is based on deception.
Hence, when able to attack, we must seem unable; when using our forces, we must seem inactive; when we are near, we must make the enemy believe we are far away; when far away, we must make him believe we are near.
Hold out baits to entice the enemy.
Feign disorder, and crush him.
If he is secure at all points, be prepared for him.
If he is in superior strength, evade him.
If your opponent is of choleric temper, seek to irritate him.
Pretend to be weak, that he may grow arrogant.
If he is taking his ease, give him no rest.
If his forces are united, separate them.
Attack him where he is unprepared, appear where you are not expected.
These military devices, leading to victory, must not be divulged beforehand.
Now the general who wins a battle makes many calculations in his temple ere the battle is fought.
The general who loses a battle makes but few calculations beforehand.
Thus do many calculations lead to victory, and few calculations to defeat: how much more no calculation at all!
It is by attention to this point that I can foresee who is likely to win or lose."""

AESOP = """A Fox one day spied a beautiful bunch of ripe grapes hanging from a vine trained along the branches of a tree.
The grapes seemed ready to burst with juice, and the Fox's mouth watered as he gazed longingly at them.
The bunch hung from a high branch, and the Fox had to jump for it.
The first time he jumped he missed the bunch by a long way.
Then he walked away and began to jump again, but he was still too far below the grapes.
At last he gave up, and walked away with his nose in the air, saying: I am sure they are sour.
It is easy to despise what you cannot get.
A Tortoise one day met a Hare, who was making fun at his slow way of moving.
The Tortoise, tired of the Hare's arrogance, challenged him to a race.
The Hare accepted, and the Fox was chosen to be the judge.
When the race began, the Hare was soon far out of sight, and thinking the Tortoise would be a long time catching up, he lay down under a tree to take a nap.
But the Tortoise kept plodding along, steady and sure, never stopping and never resting.
When the Hare woke from his nap, he saw the Tortoise near the goal, and ran as fast as he could.
But it was too late. The Tortoise had won the race.
Slow and steady wins the race.
A Wolf had been gorging himself on a feast, and a bone stuck in his throat.
In great pain he ran up and down, begging every animal he met to relieve him.
At last the Crane agreed to help, and putting his long neck down the Wolf's throat, drew out the bone.
He then asked for the reward he had been promised.
The Wolf grinned and said: You have surely had reward enough, for you put your head into a Wolf's mouth and took it out again in safety.
Those who expect gratitude from the wicked are sure to be disappointed.
The North Wind and the Sun had a quarrel about which of them was the stronger.
At last they agreed to decide the matter by seeing which could first strip a traveler of his cloak.
The North Wind began, and blew with all his might, but the harder he blew, the closer the traveler wrapped his cloak around him.
Then the Sun came out and shone in all his glory, and the traveler, finding it too hot to walk with his cloak on, took it off.
Persuasion is better than force.
A Dog was crossing a plank bridge over a stream with a piece of meat in his mouth.
He happened to look into the water and saw his own reflection.
Thinking it was another dog with a bigger piece of meat, he snapped at it.
But as he snapped, his own meat fell into the stream and was swept away.
Grasp all, lose all.
A Lion asleep in his lair was waked up by a Mouse running over his face.
Losing his temper he seized it with his paw and was about to kill it.
The Mouse, terrified, piteously begged him to spare its life.
Please let me go, it cried, and one day I will repay you for your kindness.
The idea of so insignificant a creature ever being able to do anything for him amused the Lion so much that he laughed aloud, and good-humoredly let it go.
But the Mouse's chance came after all.
One day the Lion got entangled in a net which had been spread for game by some hunters, and the Mouse heard and recognized his roars of anger.
Running to the spot, he set to work to nibble the ropes with his teeth, and succeeded before long in setting the Lion free.
There, said the Mouse, you laughed at me when I promised I would repay you: but now you see, even a Mouse can help a Lion.
Little friends may prove great friends."""

DECLARATION = """When in the Course of human events, it becomes necessary for one people to dissolve the political bands which have connected them with another, and to assume among the powers of the earth, the separate and equal station to which the Laws of Nature and of Nature's God entitle them, a decent respect to the opinions of mankind requires that they should declare the causes which impel them to the separation.
We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.
That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed.
That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.
Prudence, indeed, will dictate that Governments long established should not be changed for light and transient causes; and accordingly all experience hath shewn, that mankind are more disposed to suffer, while evils are sufferable, than to right themselves by abolishing the forms to which they are accustomed.
But when a long train of abuses and usurpations, pursuing invariably the same Object evinces a design to reduce them under absolute Despotism, it is their right, it is their duty, to throw off such Government, and to provide new Guards for their future security.
We, therefore, the Representatives of the united States of America, in General Congress, Assembled, appealing to the Supreme Judge of the world for the rectitude of our intentions, do, in the Name, and by Authority of the good People of these Colonies, solemnly publish and declare, That these United Colonies are, and of Right ought to be Free and Independent States; that they are Absolved from all Allegiance to the British Crown, and that all political connection between them and the State of Great Britain, is and ought to be totally dissolved; and that as Free and Independent States, they have full Power to levy War, conclude Peace, contract Alliances, establish Commerce, and to do all other Acts and Things which Independent States may of right do.
And for the support of this Declaration, with a firm reliance on the protection of divine Providence, we mutually pledge to each other our Lives, our Fortunes and our sacred Honor."""

GETTYSBURG = """Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.
Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure.
We are met on a great battle-field of that war.
We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.
It is altogether fitting and proper that we should do this.
But, in a larger sense, we can not dedicate, we can not consecrate, we can not hallow this ground.
The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.
The world will little note, nor long remember what we say here, but it can never forget what they did here.
It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.
It is rather for us to be here dedicated to the great task remaining before us, that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion, that we here highly resolve that these dead shall not have died in vain, that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth."""

MAGNA_CARTA = """John, by the grace of God King of England, Lord of Ireland, Duke of Normandy and Aquitaine, and Count of Anjou, to his archbishops, bishops, abbots, earls, barons, justices, foresters, sheriffs, stewards, servants, and to all his officials and loyal subjects, greeting.
Know that before God, for the health of our soul and those of our ancestors and heirs, to the honour of God, the exaltation of the holy Church, and the better ordering of our kingdom, at the advice of our reverend fathers Stephen, archbishop of Canterbury, primate of all England, and cardinal of the holy Roman Church, Henry, archbishop of Dublin, William, bishop of London, and other bishops of England, we have granted to God, and by this our present charter have confirmed, for us and our heirs in perpetuity, that the English Church shall be free, and shall have its rights undiminished, and its liberties unimpaired.
No free man shall be seized or imprisoned, or stripped of his rights or possessions, or outlawed or exiled, or deprived of his standing in any way, nor will we proceed with force against him, or send others to do so, except by the lawful judgment of his equals or by the law of the land.
To no one will we sell, to no one deny or delay right or justice.
All merchants may enter or leave England unharmed and without fear, and may stay or travel within it, by land or water, for purposes of trade, free from all illegal exactions, in accordance with ancient and lawful customs.
If any man holds land by fee-farm, either by socage or by burage, or of any escheat, and the wardship of that land falls to us, we shall have only the revenues of the land until the heir comes of age.
No constable or other bailiff of ours shall take corn or other provisions from anyone without immediately tendering money therefor, unless he can have postponement thereof by permission of the seller.
No constable shall compel a knight to pay money for castle-guard if the knight is willing to do it himself, or to have it done by another responsible man, if he is prevented from doing it by any reasonable cause.
Standard measures are to be used throughout the kingdom, for wine, ale, and corn, and for the width of dyed cloth, russet, and haberject.
In future nothing shall be paid or taken for a writ of inquisition by a man who is accused of murder, but the writ shall be granted free of charge and shall not be denied to any man.
All forests that have been afforested in our time shall at once be disafforested.
All evil customs concerning forests, warrens, foresters, warreners, sheriffs and their servants, or banks and their keepers, are at once to be investigated in every county by twelve sworn knights of the county, and within forty days of their enquiry the evil customs are to be abolished completely and irrevocably."""

EMBEDDED_BOOKS = {
    "sun_tzu": ("The Art of War (Sun Tzu, Giles translation, public domain)", SUN_TZU),
    "aesop": ("Aesop's Fables (selected, public domain)", AESOP),
    "declaration": ("The Declaration of Independence (public domain)", DECLARATION),
    "gettysburg": ("The Gettysburg Address (public domain)", GETTYSBURG),
    "magna_carta": ("Magna Carta (selected clauses, public domain)", MAGNA_CARTA),
}


def list_embedded() -> list[str]:
    """Names of every embedded book."""
    return sorted(EMBEDDED_BOOKS)


def get_embedded(name: str) -> list[str]:
    """Return an embedded book as a list of lines.

    Raises KeyError with the list of valid names when the name is unknown.
    """
    if name not in EMBEDDED_BOOKS:
        raise KeyError(f"Unknown embedded book {name!r}. Choose from: {', '.join(list_embedded())}")
    return EMBEDDED_BOOKS[name][1].splitlines()


def describe_embedded(name: str) -> str:
    """Human description of an embedded book."""
    return EMBEDDED_BOOKS[name][0]


# ---------------------------------------------------------------------------
# Procedural prose generator
# ---------------------------------------------------------------------------

_NOUNS = [
    "river", "harbor", "signal", "courier", "lantern", "archive", "bridge",
    "cipher", "letter", "station", "garden", "window", "engine", "mirror",
    "compass", "ledger", "beacon", "corridor", "attic", "harbor", "valley",
    "mountain", "village", "market", "clock", "shadow", "flame", "stone",
    "road", "field", "forest", "shore", "island", "tower", "gate",
]
_VERBS = [
    "carries", "hides", "reveals", "follows", "crosses", "guards", "marks",
    "opens", "closes", "watches", "remembers", "forgets", "signals", "waits",
    "turns", "returns", "burns", "shines", "fades", "echoes", "measures",
]
_ADJECTIVES = [
    "quiet", "distant", "ancient", "hidden", "bright", "cold", "warm",
    "narrow", "wide", "silent", "broken", "steady", "swift", "slow",
    "pale", "dark", "clear", "faint", "bold", "gentle",
]
_CONNECTORS = [
    "and", "but", "yet", "so", "then", "because", "while", "when", "after",
    "before", "although", "until", "since", "though",
]
_PLACES = [
    "by the old dock", "near the lighthouse", "under the bridge",
    "at the crossroads", "beyond the ridge", "inside the archive",
    "along the river", "past the market", "behind the gate", "above the valley",
    "through the corridor", "around the tower",
]


def generate_prose(
    paragraphs: int = 5,
    sentences_per_paragraph: int = 6,
    seed: int = 0,
    wrap: int = 72,
) -> list[str]:
    """Generate a deterministic synthetic book of readable pseudo-prose.

    The output is grammatically plausible but meaningless -- exactly what a
    cover text should be. The same seed always produces the same book, so
    tests can rely on it.

    Parameters
    ----------
    paragraphs:
        Number of paragraphs to generate.
    sentences_per_paragraph:
        Sentences inside each paragraph.
    seed:
        RNG seed for reproducibility.
    wrap:
        Soft line-wrap width. Lines are broken on word boundaries.
    """
    rng = random.Random(seed)
    lines: list[str] = []
    for _ in range(paragraphs):
        words: list[str] = []
        for _ in range(sentences_per_paragraph):
            words.extend(_sentence(rng))
        text = " ".join(words)
        lines.extend(_wrap_text(text, wrap))
        lines.append("")  # blank line between paragraphs
    while lines and not lines[-1]:
        lines.pop()
    return lines


def _sentence(rng: random.Random) -> list[str]:
    """Build one pseudo-sentence as a list of words."""
    patterns = [
        lambda: [
            _art(rng), _adj(rng), _noun(rng), _verb(rng),
            _art(rng), _noun(rng), _place(rng) + ".",
        ],
        lambda: [
            _conn(rng).capitalize(), _art(rng), _noun(rng), _verb(rng) + ",",
            _art(rng), _adj(rng), _noun(rng), _verb(rng), _place(rng) + ".",
        ],
        lambda: [
            _art(rng).capitalize(), _noun(rng), "that", _verb(rng),
            _art(rng), _noun(rng), "never", _verb(rng), _place(rng) + ".",
        ],
        lambda: [
            _art(rng).capitalize(), _adj(rng), _noun(rng), _verb(rng),
            "every", _noun(rng), "that", _verb(rng), _art(rng), _noun(rng) + ".",
        ],
    ]
    return rng.choice(patterns)()


def _art(rng: random.Random) -> str:
    return rng.choice(["the", "a", "the", "the", "a", "one"])


def _noun(rng: random.Random) -> str:
    return rng.choice(_NOUNS)


def _verb(rng: random.Random) -> str:
    return rng.choice(_VERBS)


def _adj(rng: random.Random) -> str:
    return rng.choice(_ADJECTIVES)


def _conn(rng: random.Random) -> str:
    return rng.choice(_CONNECTORS)


def _place(rng: random.Random) -> str:
    return rng.choice(_PLACES)


def _wrap_text(text: str, width: int) -> list[str]:
    """Soft-wrap a paragraph into lines no longer than 'width'."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for w in words:
        if current and length + 1 + len(w) > width:
            lines.append(" ".join(current))
            current = [w]
            length = len(w)
        else:
            current.append(w)
            length += (1 if len(current) > 1 else 0) + len(w)
    if current:
        lines.append(" ".join(current))
    return lines


# ---------------------------------------------------------------------------
# Corpus statistics
# ---------------------------------------------------------------------------

def corpus_stats(lines: Sequence[str]) -> dict:
    """High-level statistics about a book, for the stats command.

    Returns line count, word count, average words per line, the longest
    line, and a rough vocabulary size.
    """
    words = [w for line in lines for w in line.split()]
    line_lengths = [len(line.split()) for line in lines]
    return {
        "lines": len(lines),
        "non_empty_lines": sum(1 for line in lines if line.strip()),
        "words": len(words),
        "unique_words": len({w.lower() for w in words}),
        "avg_words_per_line": round(sum(line_lengths) / max(len(lines), 1), 2),
        "longest_line_words": max(line_lengths) if line_lengths else 0,
        "chars": sum(len(line) for line in lines),
    }


def make_demo_book(name: str = "sun_tzu", extra_paragraphs: int = 0, seed: int = 0) -> list[str]:
    """Build a demo book: an embedded text, optionally padded with prose.

    Useful for examples and tests that need a book of a given size without
    shipping megabytes of text.
    """
    lines = get_embedded(name)
    if extra_paragraphs > 0:
        lines = lines + [""] + generate_prose(paragraphs=extra_paragraphs, seed=seed)
    return lines


__all__ = [
    "SUN_TZU", "AESOP", "DECLARATION", "GETTYSBURG", "MAGNA_CARTA",
    "EMBEDDED_BOOKS", "list_embedded", "get_embedded", "describe_embedded",
    "generate_prose", "corpus_stats", "make_demo_book",
]
