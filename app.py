"""PromptGuard v0.1 local security dashboard."""

from pathlib import Path

import streamlit as st

from guard.adjudicator import MODEL_PATH
from guard.service import analyze_untrusted_content


st.set_page_config(
    page_title="PromptGuard | AI Agent Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>

    :root {
        color-scheme: dark;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 8% 0%, rgba(20, 184, 166, 0.15), transparent 34%),
            radial-gradient(ellipse at 95% 12%, rgba(59, 130, 246, 0.14), transparent 30%),
            linear-gradient(145deg, #070b16 0%, #0a1020 52%, #0b1222 100%);
        color: #e5eefc;
    }

    [data-testid="stHeader"] {
        background: rgba(7, 11, 22, 0.72);
        border-bottom: 1px solid rgba(148, 163, 184, 0.10);
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b1222 0%, #080e1b 100%);
        border-right: 1px solid rgba(45, 212, 191, 0.18);
    }

    [data-testid="stSidebar"] > div {
        background: transparent;
    }

    .block-container {
        max-width: 1320px;
        padding-top: 2.7rem;
        padding-bottom: 3.5rem;
    }

    .pg-eyebrow {
        display: inline-block;
        color: #5eead4;
        text-transform: uppercase;
        letter-spacing: 0.19em;
        font-weight: 800;
        font-size: 0.72rem;
        margin-bottom: 0.6rem;
        padding: 0.4rem 0.75rem;
        border: 1px solid rgba(45, 212, 191, 0.27);
        border-radius: 999px;
        background: rgba(13, 148, 136, 0.10);
    }

    h1 {
        color: #f8fafc;
        font-size: clamp(2.3rem, 5vw, 3.6rem) !important;
        font-weight: 850 !important;
        letter-spacing: -0.055em;
        line-height: 1.08 !important;
        text-shadow: 0 0 36px rgba(45, 212, 191, 0.12);
    }

    h2, h3 {
        color: #e2e8f0 !important;
        letter-spacing: -0.025em;
        font-weight: 750 !important;
    }

    .pg-subtitle {
        color: #94a3b8;
        font-size: 1.04rem;
        line-height: 1.75;
        margin-top: -0.25rem;
        margin-bottom: 1.65rem;
        max-width: 820px;
    }

    .pg-footnote {
        color: #8493aa;
        font-size: 0.83rem;
        padding-top: 0.75rem;
        letter-spacing: 0.015em;
    }

    .stMarkdown, .stText, p, li {
        color: #cbd5e1;
    }

    label, [data-testid="stWidgetLabel"] p {
        color: #dbe7f6 !important;
        font-weight: 600 !important;
    }

    [data-testid="stForm"] {
        padding: 1.45rem;
        border-radius: 22px;
        border: 1px solid rgba(100, 116, 139, 0.30);
        background: linear-gradient(
            145deg,
            rgba(15, 23, 42, 0.90),
            rgba(13, 29, 47, 0.72)
        );
        box-shadow:
            0 18px 50px rgba(0, 0, 0, 0.22),
            inset 0 1px 0 rgba(255, 255, 255, 0.035);
    }

    .stTextInput input,
    .stTextArea textarea {
        color: #e6f1ff !important;
        background: rgba(5, 11, 24, 0.80) !important;
        border: 1px solid rgba(100, 116, 139, 0.42) !important;
        border-radius: 12px !important;
        transition: border-color 160ms ease, box-shadow 160ms ease;
    }

    .stTextInput input:focus,
    .stTextArea textarea:focus {
        border-color: #2dd4bf !important;
        box-shadow: 0 0 0 2px rgba(45, 212, 191, 0.13) !important;
    }

    .stTextArea textarea {
        line-height: 1.65;
    }

    [data-testid="stFormSubmitButton"] button,
    .stButton > button {
        min-height: 2.8rem;
        color: #f0fdfa !important;
        font-weight: 750 !important;
        letter-spacing: 0.015em;
        border: 1px solid rgba(94, 234, 212, 0.48) !important;
        border-radius: 12px !important;
        background: linear-gradient(110deg, #0f766e 0%, #0891b2 100%) !important;
        box-shadow: 0 8px 24px rgba(8, 145, 178, 0.20);
        transition: transform 150ms ease, box-shadow 150ms ease;
    }

    [data-testid="stFormSubmitButton"] button:hover,
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 10px 30px rgba(45, 212, 191, 0.23);
        border-color: #5eead4 !important;
    }

    [data-testid="stMetric"] {
        padding: 1.15rem 1.2rem;
        border: 1px solid rgba(45, 212, 191, 0.20);
        border-radius: 17px;
        background: linear-gradient(
            145deg,
            rgba(15, 23, 42, 0.94),
            rgba(12, 32, 48, 0.80)
        );
        box-shadow:
            0 12px 32px rgba(0, 0, 0, 0.15),
            inset 0 1px 0 rgba(255, 255, 255, 0.035);
    }

    [data-testid="stMetricLabel"] {
        color: #9fb2c9 !important;
        font-size: 0.86rem !important;
        font-weight: 650 !important;
    }

    [data-testid="stMetricValue"] {
        color: #e6fffb !important;
        font-weight: 800 !important;
        letter-spacing: -0.035em;
    }

    [data-testid="stExpander"] {
        overflow: hidden;
        border: 1px solid rgba(100, 116, 139, 0.27);
        border-radius: 15px;
        background: rgba(11, 19, 35, 0.65);
    }

    [data-testid="stExpander"] summary {
        color: #dbeafe;
        font-weight: 650;
    }

    [data-testid="stAlert"] {
        border-radius: 14px;
        border-width: 1px;
        background: rgba(15, 23, 42, 0.72);
    }

    [data-testid="stProgress"] > div > div {
        background: linear-gradient(90deg, #14b8a6, #22d3ee);
        box-shadow: 0 0 14px rgba(45, 212, 191, 0.22);
    }

    hr {
        border-color: rgba(100, 116, 139, 0.22) !important;
        margin-top: 1.7rem !important;
        margin-bottom: 1.7rem !important;
    }

    a {
        color: #5eead4 !important;
    }

    code {
        color: #99f6e4 !important;
        background: rgba(15, 23, 42, 0.85) !important;
        border-radius: 5px;
    }

    [data-testid="stCaptionContainer"] {
        color: #8493aa;
    }

    @media (max-width: 700px) {
        .block-container {
            padding-top: 1.4rem;
            padding-left: 1rem;
            padding-right: 1rem;
        }

        [data-testid="stForm"] {
            padding: 0.9rem;
            border-radius: 16px;
        }
    }


    /* PROMPTGUARD MOTION LAYER */

    .stApp {
        background-image:
            radial-gradient(ellipse at 8% 0%, rgba(20,184,166,.15), transparent 34%),
            radial-gradient(ellipse at 95% 12%, rgba(59,130,246,.13), transparent 30%),
            linear-gradient(145deg, #070b16 0%, #0a1020 52%, #0b1222 100%),
            linear-gradient(rgba(45,212,191,.026) 1px, transparent 1px),
            linear-gradient(90deg, rgba(45,212,191,.026) 1px, transparent 1px);
        background-size: auto, auto, auto, 42px 42px, 42px 42px;
        background-attachment: fixed;
    }

    @keyframes pg-enter {
        from { opacity: 0; transform: translateY(12px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    @keyframes pg-pulse {
        0%, 100% { opacity: 1; box-shadow: 0 0 5px #2dd4bf, 0 0 12px rgba(45,212,191,.25); }
        50%      { opacity: .62; box-shadow: 0 0 10px #2dd4bf, 0 0 24px rgba(45,212,191,.48); }
    }

    @keyframes pg-orbit {
        from { transform: rotate(0deg); }
        to   { transform: rotate(360deg); }
    }

    @keyframes pg-sheen {
        0%, 60% { transform: translateX(-160%) skewX(-18deg); }
        90%, 100% { transform: translateX(240%) skewX(-18deg); }
    }

    @keyframes pg-progress-glow {
        0%, 100% { filter: brightness(1); }
        50%      { filter: brightness(1.35); }
    }

    .pg-eyebrow {
        position: relative;
        overflow: hidden;
        animation: pg-enter .65s ease-out both;
    }

    .pg-eyebrow::before {
        content: "";
        display: inline-block;
        width: 7px;
        height: 7px;
        margin-right: 9px;
        border-radius: 50%;
        vertical-align: middle;
        background: #5eead4;
        animation: pg-pulse 2.2s ease-in-out infinite;
    }

    .pg-eyebrow::after {
        content: "";
        position: absolute;
        inset: 0 auto 0 0;
        width: 28%;
        pointer-events: none;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,.15), transparent);
        animation: pg-sheen 7s ease-in-out infinite;
    }

    h1 {
        animation: pg-enter .7s .05s ease-out both;
    }

    h1::before {
        content: "◈";
        display: inline-block;
        margin-right: .24em;
        color: #2dd4bf;
        font-size: .68em;
        vertical-align: .08em;
        text-shadow: 0 0 14px rgba(45,212,191,.65);
        animation: pg-orbit 18s linear infinite;
    }

    [data-testid="stSidebar"] h2::before,
    [data-testid="stSidebar"] h3::before {
        content: "▸";
        color: #2dd4bf;
        margin-right: .55em;
        text-shadow: 0 0 12px rgba(45,212,191,.55);
    }

    [data-testid="stForm"] {
        position: relative;
        animation: pg-enter .65s .12s ease-out both;
        transition: border-color .25s ease, box-shadow .25s ease;
    }

    [data-testid="stForm"]:hover {
        border-color: rgba(45,212,191,.46);
        box-shadow:
            0 18px 54px rgba(0,0,0,.25),
            0 0 25px rgba(20,184,166,.07),
            inset 0 1px 0 rgba(255,255,255,.04);
    }

    [data-testid="stMetric"] {
        animation: pg-enter .5s ease-out both;
        transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
    }

    [data-testid="stMetric"]:hover {
        transform: translateY(-3px);
        border-color: rgba(45,212,191,.52);
        box-shadow: 0 12px 32px rgba(20,184,166,.12);
    }

    [data-testid="stProgress"] > div > div {
        animation: pg-progress-glow 3.5s ease-in-out infinite;
    }

    [data-testid="stExpander"] {
        transition: border-color .2s ease, background .2s ease;
    }

    [data-testid="stExpander"]:hover {
        border-color: rgba(45,212,191,.40);
        background: rgba(13,27,45,.85);
    }

    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            animation-duration: .01ms !important;
            animation-iteration-count: 1 !important;
            scroll-behavior: auto !important;
            transition-duration: .01ms !important;
        }
    }


    /* PROMPTGUARD SOC DASHBOARD */
    .pg-hero {
        position: relative;
        display: grid;
        grid-template-columns: 1.12fr .88fr;
        gap: 1rem;
        min-height: 325px;
        padding: 30px 30px 24px;
        margin: 0 0 22px;
        overflow: hidden;
        border: 1px solid rgba(69, 190, 205, .30);
        border-radius: 24px;
        background:
            radial-gradient(ellipse at 82% 48%, rgba(8, 145, 178, .15), transparent 39%),
            radial-gradient(ellipse at 4% 0%, rgba(20, 184, 166, .12), transparent 48%),
            linear-gradient(130deg, rgba(12, 24, 43, .98), rgba(7, 15, 30, .97));
        box-shadow: 0 22px 65px rgba(0, 0, 0, .24), inset 0 1px rgba(255,255,255,.035);
        animation: pg-hero-arrive .7s ease-out both;
    }
    .pg-hero::before {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        opacity: .32;
        background-image: linear-gradient(rgba(45,212,191,.055) 1px,transparent 1px), linear-gradient(90deg,rgba(45,212,191,.055) 1px,transparent 1px);
        background-size: 28px 28px;
        mask-image: linear-gradient(90deg,black,transparent 95%);
    }
    .pg-hero-copy, .pg-visual { position: relative; z-index: 1; min-width: 0; }
    .pg-hero-copy { display: flex; flex-direction: column; align-items: flex-start; justify-content: center; }
    .pg-kicker {
        display: inline-flex; align-items: center; gap: 9px;
        padding: 7px 11px; border: 1px solid rgba(45,212,191,.27);
        border-radius: 999px; background: rgba(13,148,136,.09);
        color: #76f5df; font-size: .67rem; font-weight: 800; letter-spacing: .16em;
    }
    .pg-live-dot, .pg-status-dot, .pg-mini-dot {
        display: inline-block; width: 7px; height: 7px; flex: 0 0 7px;
        border-radius: 50%; background: #5eead4; box-shadow: 0 0 10px rgba(45,212,191,.8);
    }
    .pg-live-dot { animation: pg-status-pulse 2s infinite; }
    .pg-hero-title {
        margin-top: 22px; max-width: 590px;
        color: #f0f8ff; font-size: clamp(2.2rem, 4vw, 3.75rem);
        line-height: 1.02; font-weight: 850; letter-spacing: -.055em;
    }
    .pg-hero-title span {
        color: #72e5e0;
        background: linear-gradient(95deg, #5eead4 5%, #67e8f9 52%, #a5b4fc 100%);
        -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
        filter: drop-shadow(0 0 18px rgba(45,212,191,.12));
    }
    .pg-hero-subtitle { max-width: 500px; margin: 15px 0 17px; color: #9fb5ca; font-size: .96rem; line-height: 1.65; }
    .pg-hero-tags { display: flex; flex-wrap: wrap; gap: 8px; }
    .pg-hero-tags span { padding: 7px 10px; color: #c9d8e7; border: 1px solid rgba(113,146,172,.23); border-radius: 8px; background: rgba(10,24,40,.66); font-size: .68rem; letter-spacing: .08em; }
    .pg-hero-tags b { margin-right: 5px; color: #5eead4; }
    .pg-hero-foot { margin-top: 23px; color: #708ca6; font-size: .61rem; letter-spacing: .12em; }
    .pg-status-dot { width: 6px; height: 6px; margin-right: 7px; vertical-align: 1px; }
    .pg-visual { display: flex; align-items: center; justify-content: center; min-height: 265px; }
    .pg-cyber-stage { position: relative; width: 320px; height: 260px; max-width: 100%; isolation: isolate; }
    .pg-ring { position: absolute; top: 50%; left: 50%; border: 1px solid rgba(45,212,191,.27); border-radius: 50%; transform: translate(-50%,-50%); }
    .pg-ring-outer { width: 218px; height: 218px; border-style: dashed; border-color: rgba(45,212,191,.35); animation: pg-orbit-clockwise 32s linear infinite; }
    .pg-ring-middle { width: 174px; height: 174px; border-color: rgba(56,189,248,.38); border-top: 2px solid #38bdf8; border-bottom: 2px solid #2dd4bf; animation: pg-orbit-counter 22s linear infinite; }
    .pg-ring-inner { width: 126px; height: 126px; border-style: dotted; border-color: rgba(103,232,249,.42); }
    .pg-crosshair { position: absolute; top: 50%; left: 50%; background: rgba(45,212,191,.16); }
    .pg-crosshair-horizontal { width: 264px; height: 1px; transform: translate(-50%,-50%); }
    .pg-crosshair-vertical { width: 1px; height: 230px; transform: translate(-50%,-50%); }
    .pg-network-node { position: absolute; z-index: 2; width: 7px; height: 7px; border-radius: 50%; background: #67e8f9; box-shadow: 0 0 12px rgba(103,232,249,.9); animation: pg-nodes-pulse 2.8s ease-in-out infinite; }
    .pg-node-one { left: 18%; top: 20%; }
    .pg-node-two { right: 17%; top: 17%; animation-delay: .4s; }
    .pg-node-three { right: 10%; top: 49%; animation-delay: .8s; }
    .pg-node-four { right: 25%; bottom: 12%; animation-delay: 1.2s; }
    .pg-node-five { left: 15%; bottom: 20%; animation-delay: 1.6s; }
    .pg-node-six { left: 8%; top: 47%; animation-delay: 2s; }
    .pg-shield { position: absolute; z-index: 3; top: 50%; left: 50%; width: 89px; height: 106px; transform: translate(-50%,-50%); clip-path: polygon(50% 0, 94% 15%, 90% 58%, 75% 81%, 50% 100%, 25% 81%, 10% 58%, 6% 15%); background: linear-gradient(135deg,#67e8f9,#2dd4bf 55%,#0e7490); filter: drop-shadow(0 0 15px rgba(45,212,191,.42)); animation: pg-shield-float 3.6s ease-in-out infinite; }
    .pg-shield-face { position: absolute; inset: 3px; display: grid; place-items: center; clip-path: polygon(50% 0, 94% 15%, 90% 58%, 75% 81%, 50% 100%, 25% 81%, 10% 58%, 6% 15%); background: linear-gradient(145deg,#102c40,#091626 75%); }
    .pg-shield-face span { color: #99f6e4; font-size: 2.5rem; font-weight: 800; text-shadow: 0 0 18px rgba(94,234,212,.8); }
    .pg-scan-beam { position: absolute; z-index: 4; left: 50%; top: 50%; width: 230px; height: 1px; pointer-events: none; background: linear-gradient(90deg,transparent,rgba(103,232,249,.95),transparent); box-shadow: 0 0 9px rgba(103,232,249,.45); animation: pg-radar-scan 3.8s ease-in-out infinite; }
    .pg-visual-caption, .pg-visual-footer { position: absolute; z-index: 2; color: #6e91a9; font-size: .59rem; font-weight: 750; letter-spacing: .13em; }
    .pg-visual-caption { top: 2px; right: 5px; }
    .pg-visual-caption span { margin-left: 8px; color: #5eead4; }
    .pg-visual-footer { bottom: 0; right: 10px; }
    .pg-visual-footer span { color: #5eead4; font-size: .9rem; }
    .pg-orbit-spin { transform-origin: 180px 143px; animation: pg-orbit-clockwise 28s linear infinite; }
    .pg-orbit-reverse { transform-origin: 180px 143px; animation: pg-orbit-counter 20s linear infinite; }
    .pg-scan-beam { transform-origin: 180px 143px; animation: pg-radar-scan 3.6s ease-in-out infinite; }
    .pg-center-pulse { transform-origin: 180px 143px; animation: pg-core-pulse 2.4s ease-in-out infinite; }
    .pg-network-nodes { animation: pg-nodes-pulse 3.5s ease-in-out infinite; }
    .pg-section-label { display: flex; justify-content: space-between; gap: 12px; margin: 7px 2px 12px; color: #69869f; font-size: .65rem; font-weight: 750; letter-spacing: .14em; }
    .pg-section-label span:first-child { color: #9cb4ca; }
    .pg-module-grid { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 12px; margin-bottom: 17px; }
    .pg-module-card {
        min-width: 0; padding: 17px 17px 15px; border-radius: 16px;
        border: 1px solid rgba(83,128,160,.23);
        background: linear-gradient(145deg, rgba(17,31,51,.88), rgba(10,20,36,.88));
        box-shadow: inset 0 1px rgba(255,255,255,.025);
        transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease;
        animation: pg-card-arrive .6s ease-out both;
    }
    .pg-module-card:nth-child(2) { animation-delay: .07s; }
    .pg-module-card:nth-child(3) { animation-delay: .14s; }
    .pg-module-card:nth-child(4) { animation-delay: .21s; }
    .pg-module-card:hover { transform: translateY(-4px); border-color: rgba(45,212,191,.48); box-shadow: 0 12px 30px rgba(0,0,0,.18), 0 0 24px rgba(20,184,166,.06); }
    .pg-card-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 13px; }
    .pg-module-number { color: #56748d; font: 700 .68rem ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .10em; }
    .pg-module-symbol { display: grid; place-items: center; width: 32px; height: 32px; color: #68e9df; border: 1px solid rgba(45,212,191,.25); border-radius: 10px; background: rgba(20,184,166,.08); font-size: 1.3rem; }
    .pg-module-card:nth-child(2) .pg-module-symbol { color: #7dd3fc; border-color: rgba(56,189,248,.25); background: rgba(56,189,248,.07); }
    .pg-module-card:nth-child(3) .pg-module-symbol { color: #c4b5fd; border-color: rgba(167,139,250,.25); background: rgba(167,139,250,.07); }
    .pg-module-card:nth-child(4) .pg-module-symbol { color: #fcd38d; border-color: rgba(251,191,36,.25); background: rgba(251,191,36,.06); }
    .pg-module-title { color: #dce9f7; font-size: .72rem; font-weight: 800; letter-spacing: .035em; }
    .pg-module-copy { min-height: 48px; margin-top: 7px; color: #829bb2; font-size: .76rem; line-height: 1.55; }
    .pg-card-bottom { display: flex; align-items: center; gap: 7px; margin-top: 12px; padding-top: 11px; border-top: 1px solid rgba(100,116,139,.15); color: #64829a; font-size: .57rem; font-weight: 750; letter-spacing: .09em; }
    .pg-mini-dot { width: 5px; height: 5px; flex-basis: 5px; }
    .pg-mini-dot.blue { background: #38bdf8; box-shadow: 0 0 8px rgba(56,189,248,.75); }
    .pg-mini-dot.violet { background: #a78bfa; box-shadow: 0 0 8px rgba(167,139,250,.75); }
    .pg-mini-dot.amber { background: #fbbf24; box-shadow: 0 0 8px rgba(251,191,36,.65); }
    .pg-security-note { display: flex; align-items: flex-start; gap: 12px; margin: 0 0 22px; padding: 14px 17px; border: 1px solid rgba(56,189,248,.20); border-radius: 13px; background: linear-gradient(105deg, rgba(14,116,144,.13), rgba(15,23,42,.48)); }
    .pg-note-icon { display: grid; place-items: center; width: 24px; height: 24px; flex: 0 0 24px; border: 1px solid rgba(103,232,249,.3); border-radius: 50%; color: #67e8f9; font-weight: 850; }
    .pg-security-note strong { color: #dff9ff; font-size: .82rem; }
    .pg-security-note p { margin: 3px 0 0; color: #89a7be; font-size: .77rem; line-height: 1.55; }
    @keyframes pg-hero-arrive { from { opacity: 0; transform: translateY(9px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pg-card-arrive { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pg-status-pulse { 0%,100% { opacity: 1; box-shadow: 0 0 5px #5eead4; } 50% { opacity: .45; box-shadow: 0 0 13px #5eead4; } }
    @keyframes pg-orbit-clockwise { to { transform: rotate(360deg); } }
    @keyframes pg-orbit-counter { from { transform: rotate(360deg); } to { transform: rotate(0); } }
    @keyframes pg-radar-scan { 0%,100% { opacity: .12; transform: translate(-50%,-72px); } 50% { opacity: .95; transform: translate(-50%,72px); } } 50% { opacity: 1; transform: translateY(52px); } }
    @keyframes pg-shield-float { 0%,100% { margin-top: 0; } 50% { margin-top: -5px; } }
    @keyframes pg-core-pulse { 0%,100% { opacity: .55; transform: scale(.8); } 50% { opacity: 1; transform: scale(1.35); } }
    @keyframes pg-nodes-pulse { 0%,100% { opacity: .67; } 50% { opacity: 1; } }
    @media (max-width: 950px) {
        .pg-hero { grid-template-columns: 1fr; padding: 24px; }
        .pg-visual { min-height: 230px; }
        .pg-cyber-stage { transform: scale(.92); }
        .pg-module-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }
        .pg-hero-title { font-size: clamp(2.2rem, 7vw, 3.4rem); }
    }
    @media (max-width: 520px) {
        .pg-hero { padding: 19px; }
        .pg-module-grid { grid-template-columns: 1fr; }
        .pg-module-copy { min-height: 0; }
        .pg-hero-tags { gap: 5px; }
        .pg-hero-tags span { font-size: .61rem; padding: 6px 8px; }
        .pg-section-label { font-size: .55rem; }
    }
    @media (prefers-reduced-motion: reduce) {
        .pg-hero, .pg-live-dot, .pg-orbit-spin, .pg-orbit-reverse,
        .pg-scan-beam, .pg-center-pulse, .pg-network-nodes, .pg-network-node, .pg-shield, .pg-module-card {
            animation: none !important;
            transition: none !important;
        }
    }

    </style>
    """,
    unsafe_allow_html=True,
)

model_file = Path(MODEL_PATH)

with st.sidebar:
    st.markdown("## 🛡️ PromptGuard")
    st.caption("Local AI-agent security")
    st.divider()

    st.markdown("#### Runtime")
    if model_file.is_file():
        st.success("Local adjudicator model found")
    else:
        st.error("Adjudicator model not found")

    st.caption("Configured model path")
    st.code(str(model_file), language=None)

    st.divider()
    st.markdown("#### Pipeline")
    st.write("1. Rule-based detection")
    st.write("2. Semantic analysis")
    st.write("3. Local model review when needed")
    st.write("4. Policy decision")
    st.write("5. Security decision record")

    st.divider()
    st.caption("v0.1 · Experimental security prototype")

st.markdown(
    r"""
    <section class="pg-hero">
      <div class="pg-hero-copy">
        <div class="pg-kicker"><span class="pg-live-dot"></span> AI SECURITY OPERATIONS</div>
        <div class="pg-hero-title">Secure the <span>AI workflow.</span></div>
        <p class="pg-hero-subtitle">
          Inspect untrusted content before it reaches your agent.
          Detect suspicious instructions. Make risk-aware decisions.
        </p>
        <div class="pg-hero-tags">
          <span><b>01</b> DETECT</span>
          <span><b>02</b> ASSESS</span>
          <span><b>03</b> DECIDE</span>
        </div>
        <div class="pg-hero-foot">
          <span class="pg-status-dot"></span>
          LOCAL-FIRST&nbsp; / &nbsp;DEFENSE IN DEPTH&nbsp; / &nbsp;PROMPTGUARD V0.1
        </div>
      </div>

      <div class="pg-visual" aria-label="Decorative animated security shield">
        <div class="pg-visual-caption">SECURITY CORE <span>● READY</span></div>
        <div class="pg-cyber-stage" role="img" aria-label="Decorative animated cybersecurity radar">
          <div class="pg-ring pg-ring-outer"></div>
          <div class="pg-ring pg-ring-middle"></div>
          <div class="pg-ring pg-ring-inner"></div>
          <div class="pg-crosshair pg-crosshair-horizontal"></div>
          <div class="pg-crosshair pg-crosshair-vertical"></div>
          <div class="pg-network-node pg-node-one"></div>
          <div class="pg-network-node pg-node-two"></div>
          <div class="pg-network-node pg-node-three"></div>
          <div class="pg-network-node pg-node-four"></div>
          <div class="pg-network-node pg-node-five"></div>
          <div class="pg-network-node pg-node-six"></div>
          <div class="pg-shield">
            <div class="pg-shield-face"><span>✓</span></div>
          </div>
          <div class="pg-scan-beam"></div>
        </div>
        <div class="pg-visual-footer"><span>◈</span> TRUST NOTHING BY DEFAULT</div>
      </div>
    </section>

    <div class="pg-section-label"><span>01 / DEFENSE MODULES</span><span>LOCAL ANALYSIS PIPELINE</span></div>
    <section class="pg-module-grid">
      <div class="pg-module-card">
        <div class="pg-card-top"><span class="pg-module-number">01</span><span class="pg-module-symbol">⌕</span></div>
        <div class="pg-module-title">RULE DETECTION</div>
        <div class="pg-module-copy">Inspect known patterns and suspicious directives.</div>
        <div class="pg-card-bottom"><span class="pg-mini-dot"></span> PATTERN ANALYSIS</div>
      </div>
      <div class="pg-module-card">
        <div class="pg-card-top"><span class="pg-module-number">02</span><span class="pg-module-symbol">◎</span></div>
        <div class="pg-module-title">SEMANTIC ANALYSIS</div>
        <div class="pg-module-copy">Compare content against semantic risk signals.</div>
        <div class="pg-card-bottom"><span class="pg-mini-dot blue"></span> CONTEXT SIGNALS</div>
      </div>
      <div class="pg-module-card">
        <div class="pg-card-top"><span class="pg-module-number">03</span><span class="pg-module-symbol">✳</span></div>
        <div class="pg-module-title">LOCAL ADJUDICATOR</div>
        <div class="pg-module-copy">Request model review when the policy pipeline calls for it.</div>
        <div class="pg-card-bottom"><span class="pg-mini-dot violet"></span> ON-DEMAND REVIEW</div>
      </div>
      <div class="pg-module-card">
        <div class="pg-card-top"><span class="pg-module-number">04</span><span class="pg-module-symbol">⛨</span></div>
        <div class="pg-module-title">POLICY ENGINE</div>
        <div class="pg-module-copy">Route the result to ALLOW, QUARANTINE, or BLOCK.</div>
        <div class="pg-card-bottom"><span class="pg-mini-dot amber"></span> RISK-BASED DECISION</div>
      </div>
    </section>

    <div class="pg-security-note">
      <span class="pg-note-icon">!</span>
      <div><strong>Content remains untrusted during analysis.</strong>
      <p>PromptGuard does not execute embedded instructions or perform external actions. An ALLOW decision is not a guarantee that content is safe.</p></div>
    </div>
    """,
    unsafe_allow_html=True,
)

if not model_file.is_file():
    st.error(
        "Analysis is disabled because the configured local adjudicator model "
        "does not exist. Set PROMPTGUARD_GGUF_PATH to a valid GGUF model file "
        "and restart the dashboard. No content has been analyzed."
    )
    st.stop()

with st.form("content_analysis_form"):
    source = st.text_input(
        "Source label",
        value="manual_input",
        max_chars=80,
        help="A short label for the origin of this content, such as email or document.",
    )

    content = st.text_area(
        "Untrusted content",
        height=260,
        max_chars=100_000,
        placeholder=(
            "Paste the text you want to inspect here..."
        ),
        help="Maximum 100,000 characters per submission.",
    )

    submitted = st.form_submit_button(
        "Analyze content",
        type="primary",
        use_container_width=True,
    )

if submitted:
    if not content.strip():
        st.error("Enter some content before starting the analysis.")
    elif not source.strip():
        st.error("Enter a source label.")
    else:
        try:
            with st.spinner(
                "Analyzing content with the configured local security pipeline..."
            ):
                result = analyze_untrusted_content(
                    content,
                    source=source.strip(),
                )
        except Exception as exc:
            st.error(
                "Analysis failed. No ALLOW decision was produced. "
                "Do not treat this content as trusted."
            )
            st.caption(
                f"Diagnostic: {type(exc).__name__}. "
                "Check the model configuration and local logs."
            )
        else:
            st.divider()
            st.markdown("### Security decision")

            action = result.policy.action.value
            risk = max(0.0, min(1.0, float(result.final_risk)))

            if action == "ALLOW":
                st.success(
                    "ALLOW — The content passed the current configured checks. "
                    "This is not a guarantee that it is safe."
                )
            elif action == "QUARANTINE":
                st.warning(
                    "QUARANTINE — Keep this content isolated. "
                    "Do not follow its embedded instructions."
                )
            else:
                st.error(
                    "BLOCK — The content reached the configured high-risk "
                    "threshold. Do not use it as trusted input."
                )

            metric_columns = st.columns(3)
            metric_columns[0].metric("Policy action", action)
            metric_columns[1].metric("Final risk score", f"{risk:.2f} / 1.00")
            metric_columns[2].metric(
                "Adjudicator used",
                "Yes" if result.adjudication_performed else "No",
            )

            st.progress(risk, text=f"Final risk score: {risk:.0%}")

            with st.expander("Detection and analysis details", expanded=True):
                assessment = result.assessment
                left, right = st.columns(2)

                with left:
                    st.markdown("**Rule and semantic signals**")
                    st.write(f"Rule risk: {assessment.rule_risk:.2f}")
                    st.write(
                        f"Semantic margin: {assessment.semantic_margin:+.3f}"
                    )
                    st.write(
                        f"Semantic signal: {assessment.semantic_signal}"
                    )
                    st.write(f"Decision path: {result.decision_path}")

                with right:
                    st.markdown("**Detection reasons**")
                    if result.reasons:
                        for reason in result.reasons:
                            st.write(f"• {reason}")
                    else:
                        st.write("No specific detection reasons were recorded.")

                if result.adjudicator_result is not None:
                    st.markdown("**Local model review**")
                    st.write(
                        "Label: "
                        + str(result.adjudicator_result.get("label", "UNKNOWN"))
                    )
                    st.write(
                        "Valid output: "
                        + str(
                            result.adjudicator_result.get("valid", False)
                        )
                    )
                    if result.adjudicator_result.get("reason"):
                        st.write(
                            "Reason: "
                            + str(result.adjudicator_result["reason"])
                        )

            with st.expander("Security decision record"):
                decision = result.security_decision
                st.write(f"Source: {decision.source}")
                st.write(f"Content length: {decision.content_length}")
                st.write(f"SHA-256: `{decision.content_hash}`")
                st.write(f"Policy action: {decision.action}")
                st.write(f"Safe flag: {decision.safe}")
                st.write(f"Policy reason: {decision.policy_reason}")

            if result.quarantine_record is not None:
                with st.expander("Quarantine record"):
                    st.write(result.quarantine_record.summary())
                    st.write(
                        "The record exists in this application process; "
                        "this dashboard does not provide persistent quarantine "
                        "storage or a review queue."
                    )

st.divider()
st.markdown("### Current version limitations")
st.markdown(
    """
    - Detection is heuristic and model-dependent; false positives and missed
      attacks are possible.
    - This version does not establish reliable task-aware attribution for
      every quoted or embedded instruction.
    - The document source is supplied manually; production integrations with
      external agents and tools are not included in this dashboard.
    - Quarantine records are in-memory objects, not a durable audit store.
    - The dashboard does not provide authentication or multi-user access
      controls. Use it locally, not as a public service.
    """
)

st.markdown(
    '<div class="pg-footnote">'
    "PromptGuard v0.1 development build · Review security decisions before "
    "using content in sensitive workflows."
    "</div>",
    unsafe_allow_html=True,
)
