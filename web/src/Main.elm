module Main exposing (..)

import Browser
import Browser.Navigation as Nav
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick)
import Http
import Json.Decode as D
import Json.Decode.Pipeline as Pipeline
import Process
import RemoteData exposing (WebData)
import Task
import UUID exposing (UUID)
import Url



-- MAIN


main : Program D.Value Model Msg
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
    , servers : List (WebData Server)
    , activeServer : Maybe Server
    , keyViewers : Int
    }


type alias Flags =
    { serverUrls : List String }


type alias Server =
    { url : String
    , namespace : UUID
    }


flagsDecoder : D.Decoder Flags
flagsDecoder =
    D.succeed Flags
        |> Pipeline.required "servers" (D.list D.string)


init : D.Value -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init flags url key =
    let
        getNsCmds =
            D.decodeValue flagsDecoder flags
                |> Result.map .serverUrls
                |> Result.withDefault [ "http://localhost:8008" ]
                |> List.map getServerNamespace
                |> Cmd.batch
    in
    ( { key = key
      , url = url
      , servers = []
      , activeServer = Nothing
      , keyViewers = 0
      }
    , getNsCmds
    )



-- UPDATE


type Msg
    = LinkClicked Browser.UrlRequest
    | UrlChanged Url.Url
    | GenerateKey
    | ForgetKeys
    | GotServer String (Result Http.Error UUID)
    | DeleteFailedServers


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

        GotServer url (Ok namespace) ->
            let
                server =
                    RemoteData.Success { url = url, namespace = namespace }
            in
            ( { model | servers = server :: model.servers }, Cmd.none )

        GotServer _ (Err e) ->
            let
                cmd =
                    Process.sleep 5000 |> Task.perform (always DeleteFailedServers)
            in
            ( { model | servers = RemoteData.Failure e :: model.servers }, cmd )

        DeleteFailedServers ->
            ( { model
                | servers =
                    model.servers
                        |> List.filterMap RemoteData.toMaybe
                        |> List.map RemoteData.Success
              }
            , Cmd.none
            )


{-| getServerNamespace validates server url by fetching the namespace from it.
-}
getServerNamespace : String -> Cmd Msg
getServerNamespace url =
    Http.request
        { method = "GET"
        , headers = [ Http.header "Accept" "application/octet-stream" ]
        , url = url ++ "/namespace"
        , body = Http.emptyBody
        , expect = Http.expectBytes (GotServer url) UUID.decoder
        , timeout = Nothing
        , tracker = Nothing
        }



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
            , viewNavRight model.activeServer |> div [ class "nav-right" ]
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
                [ h2 [] [ text "Servers" ]
                , viewServers model.servers |> select []
                ]
            , section []
                [ h2 [] [ text "Keys" ]
                , button [ class "button primary", onClick GenerateKey ] [ text "Generate Key" ]
                , button [ class "button error", onClick ForgetKeys ] [ text "Forget Keys" ]
                , viewIdentities model.keyViewers model.activeServer |> div []
                ]
            ]
        ]
    }


viewNavRight : Maybe Server -> List (Html Msg)
viewNavRight activeServer =
    case activeServer of
        Nothing ->
            []

        Just server ->
            [ viewNamespace server.namespace ]


viewNamespace : UUID -> Html Msg
viewNamespace namespace =
    [ p []
        [ span [] [ text "Namespace " ]
        , strong
            [ id "namespace", class "text-primary" ]
            [ namespace |> UUID.toString |> text ]
        ]
    ]
        |> a []


viewServers : List (WebData Server) -> List (Html Msg)
viewServers servers =
    servers
        |> List.map viewServer


viewServer : WebData Server -> Html Msg
viewServer server =
    case server of
        RemoteData.NotAsked ->
            div [ class "server" ] [ text "Not Asked" ]

        RemoteData.Loading ->
            div [ class "server" ] [ text "Loading" ]

        RemoteData.Failure _ ->
            div [ class "server" ] [ text <| "Failed" ]

        RemoteData.Success s ->
            option
                [ value s.url ]
                [ s.url ++ " (" ++ UUID.toString s.namespace ++ ")" |> text ]


viewIdentities : Int -> Maybe Server -> List (Html Msg)
viewIdentities n activeServer =
    let
        caUrl =
            Maybe.withDefault "" <| Maybe.map .url activeServer
    in
    node "key-viewer"
        [ attribute "ca-url" caUrl ]
        []
        |> List.repeat n
