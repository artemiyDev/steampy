from dataclasses import dataclass
from enum import IntEnum


@dataclass(frozen=True)
class GameOptions:
    app_id: str
    context_id: str


GameOptions.STEAM = GameOptions('753', '6')
GameOptions.DOTA2 = GameOptions('570', '2')
GameOptions.CS = GameOptions('730', '2')
GameOptions.TF2 = GameOptions('440', '2')
GameOptions.PUBG = GameOptions('578080', '2')
GameOptions.RUST = GameOptions('252490', '2')


@dataclass(frozen=True)
class Asset:
    asset_id: str
    game: GameOptions
    amount: int = 1

    def to_dict(self) -> dict:
        return {
            'appid': int(self.game.app_id),
            'contextid': self.game.context_id,
            'amount': self.amount,
            'assetid': self.asset_id,
        }


class Currency(IntEnum):
    USD = 1
    GBP = 2
    EURO = 3
    CHF = 4
    RUB = 5
    PLN = 6
    BRL = 7
    JPY = 8
    NOK = 9
    IDR = 10
    MYR = 11
    PHP = 12
    SGD = 13
    THB = 14
    VND = 15
    KRW = 16
    TRY = 17
    UAH = 18
    MXN = 19
    CAD = 20
    AUD = 21
    NZD = 22
    CNY = 23
    INR = 24
    CLP = 25
    PEN = 26
    COP = 27
    ZAR = 28
    HKD = 29
    TWD = 30
    SAR = 31
    AED = 32
    SEK = 33
    ARS = 34
    ILS = 35
    BYN = 36
    KZT = 37
    KWD = 38
    QAR = 39
    CRC = 40
    UYU = 41
    BGN = 42
    HRK = 43
    CZK = 44
    DKK = 45
    HUF = 46
    RON = 47


class TradeOfferState(IntEnum):
    Invalid = 1
    Active = 2
    Accepted = 3
    Countered = 4
    Expired = 5
    Canceled = 6
    Declined = 7
    InvalidItems = 8
    ConfirmationNeed = 9
    CanceledBySecondaryFactor = 10
    StateInEscrow = 11


class SteamUrl:
    API_URL = 'https://api.steampowered.com'
    COMMUNITY_URL = 'https://steamcommunity.com'
    STORE_URL = 'https://store.steampowered.com'
    LOGIN_URL = 'https://login.steampowered.com'


class Endpoints:
    CHAT_LOGIN = f'{SteamUrl.API_URL}/ISteamWebUserPresenceOAuth/Logon/v1'
    SEND_MESSAGE = f'{SteamUrl.API_URL}/ISteamWebUserPresenceOAuth/Message/v1'
    CHAT_LOGOUT = f'{SteamUrl.API_URL}/ISteamWebUserPresenceOAuth/Logoff/v1'
    CHAT_POLL = f'{SteamUrl.API_URL}/ISteamWebUserPresenceOAuth/Poll/v1'


DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36'
)
