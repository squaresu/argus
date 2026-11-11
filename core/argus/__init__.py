"""Argus: checks AI agent skills with several open-source security scanners and explains the result in Traditional Chinese.

Named after Argus Panoptes, the hundred-eyed watchman of Greek myth: several scanners keep watch together.
The core uses only Python's standard library; each scanner is installed as its own uv tool.
"""

NAME = 'Argus'
TAGLINE = 'AI 技能安全掃描'
VERSION = '2.2.2'
COPYRIGHT = '© 2026 Square Su'
LICENSE = 'MIT'

# shown on the page, in the About dialog and at the foot of every report
DISCLAIMER_SHORT = '掃描結果僅供參考，不保證技能安全；可能誤判，也可能漏判。要不要安裝，請自行判斷。'
DISCLAIMER = (
    '掃描結果僅供參考，不代表技能一定安全或一定有害。各掃描工具只能找出已知的寫法，可能誤判，也可能漏掉新的或刻意隱藏的手法；'
    '「多半不用擔心」是依固定規則分的組，不代表一定沒問題。是否安裝、如何使用，由你自行判斷並承擔風險。'
    'Argus 依 MIT 授權「按現狀」提供，不附任何保證，作者不對使用本工具或依結果所做的決定造成的任何損失負責。'
    'Argus 是獨立的開源專案，與 NVIDIA、Cisco、PyCQA、Yelp、Anthropic 等公司或組織無關，也沒有獲得它們的背書。'
)
