module Main exposing (..)

import Array exposing (Array)
import Browser
import Browser.Navigation as Nav
import Html exposing (..)
import Html.Attributes exposing (alt, attribute, class, href, id, src)
import Html.Events exposing (onClick)
import Url



-- MAIN


main : Program () Model Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = LinkClicked
        }



-- MODEL


type alias Model =
    { key : Nav.Key
    , url : Url.Url
    , servers : Array String
    , activeServer : String
    , keyViewers : Int
    }


init : () -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init _ url key =
    ( { key = key
      , url = url
      , servers = Array.fromList [ "http://localhost:8008" ]
      , activeServer = "http://localhost:8008"
      , keyViewers = 0
      }
    , Cmd.none
    )



-- UPDATE


type Msg
    = LinkClicked Browser.UrlRequest
    | UrlChanged Url.Url
    | GenerateKey
    | ForgetKeys


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        LinkClicked urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.pushUrl model.key (Url.toString url) )

                Browser.External href ->
                    ( model, Nav.load href )

        UrlChanged url ->
            ( { model | url = url }
            , Cmd.none
            )

        GenerateKey ->
            ( { model | keyViewers = model.keyViewers + 1 }, Cmd.none )

        ForgetKeys ->
            ( { model | keyViewers = 0 }, Cmd.none )



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none



-- VIEW


view : Model -> Browser.Document Msg
view model =
    { title = "URL Interceptor"
    , body =
        [ nav [ class "nav" ]
            [ div [ class "nav-left" ]
                [ a [ class "brand" ]
                    [ img [ src "/bifrost.webp", alt "Bifrost" ] []
                    , text "Bifrost"
                    ]
                ]
            , div [ class "nav-right" ]
                [ a []
                    [ p []
                        [ span [] [ text "Namespace " ]
                        , strong [ id "namespace", class "text-primary" ] []
                        ]
                    ]
                ]
            ]
        , header [ class "container" ]
            [ node "hgroup"
                []
                [ h1 [] [ text "Certificate Issuer" ]
                , p [] [ text "Hot off the presses!" ]
                ]
            ]
        , main_ [ class "container" ]
            [ section []
                [ h2 [] [ text "Keys" ]
                , button [ class "button primary", onClick GenerateKey ] [ text "Generate Key" ]
                , button [ class "button error", onClick ForgetKeys ] [ text "Forget Keys" ]
                ]
            , section []
                [ h2 [] [ text "Identities" ]
                , div [] <| List.repeat model.keyViewers <| node "key-viewer" [ attribute "ca-url" model.activeServer ] []
                ]
            ]
        ]
    }
