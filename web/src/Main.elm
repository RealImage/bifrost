module Main exposing (Msg(..), main, update, view)

import Array exposing (Array)
import Browser
import File exposing (File)
import File.Select
import Html exposing (Html, main_, text)
import Html.Attributes exposing (class)
import Html.Events exposing (onClick)
import Http
import RemoteData exposing (RemoteData, WebData)
import Task
import UUID exposing (UUID)


type alias Model =
    { namespace : RemoteData String UUID
    , requests : Array Request
    }


type alias Request =
    { crt : WebData String
    , key : String
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { namespace = RemoteData.Loading
      , requests = Array.empty
      }
    , Http.get { expect = Http.expectString GotNamespace, url = "/namespace" }
    )


type Msg
    = GotNamespace (Result Http.Error String)
    | OpenFilesClicked
    | FilesSelected File (List File)
    | FileRead String


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        GotNamespace r ->
            ( { model | namespace = gotNamespace r }, Cmd.none )

        OpenFilesClicked ->
            let
                mimes =
                    [ "application/octet-stream", "text/plain", ".pem", ".der", ".cer", ".crt" ]
            in
            ( model, File.Select.files mimes FilesSelected )

        FilesSelected file files ->
            let
                readFile f =
                    Task.perform FileRead <| File.toString f
            in
            ( model, Cmd.batch <| List.map readFile <| file :: files )

        FileRead string ->
            ( { model
                | requests =
                    Array.push
                        { crt = RemoteData.Loading
                        , key = string
                        }
                        model.requests
              }
            , Cmd.none
            )


gotNamespace : Result Http.Error String -> RemoteData String UUID
gotNamespace res =
    case res of
        Result.Ok s ->
            case UUID.fromString s of
                Result.Ok uuid ->
                    RemoteData.Success uuid

                Result.Err _ ->
                    RemoteData.Failure "Error parsing namespace"

        Result.Err _ ->
            RemoteData.Failure "Error fetching namespace"


view : Model -> Browser.Document Msg
view model =
    let
        ( title, body ) =
            case model.namespace of
                RemoteData.NotAsked ->
                    ( "", [] )

                RemoteData.Loading ->
                    ( "Bifrost", [ Html.text "Loading" ] )

                RemoteData.Failure e ->
                    ( "zen meditation error"
                    , [ Html.h1 [] [ text e ] ]
                    )

                RemoteData.Success ns ->
                    ( "Bifrost Certificate Issuer"
                    , viewIssuer model <| UUID.toString ns
                    )
    in
    { title = title
    , body = body
    }


viewIssuer : Model -> String -> List (Html Msg)
viewIssuer model ns =
    [ Html.nav [ class "nav" ]
        [ Html.div
            [ class "nav-left" ]
            [ Html.a [ class "brand" ] [ text "Bifrost" ] ]
        , Html.div
            [ class "nav-right" ]
            [ Html.a [] [ text ns ] ]
        ]
    , Html.header [ class "container" ]
        [ Html.node "hgroup"
            []
            [ Html.h1 [] [ text "Certificate Issuer" ]
            , Html.p [] [ text "Hot off the presses" ]
            ]
        , Html.section []
            [ Html.h2 [] [ text "New Request" ]
            , Html.button
                [ class "button" ]
                [ text "Generate private key" ]
            , Html.button
                [ class "button", onClick OpenFilesClicked ]
                [ text "Upload private keys" ]
            ]
        ]
    , main_ [ class "container" ]
        [ Html.section []
            [ Html.h2 [] [ text "Requests" ]
            , Html.div [ class "row" ] <| Array.foldl viewRequests [] model.requests
            ]
        ]
    ]


viewRequests : Request -> List (Html a) -> List (Html a)
viewRequests r acc =
    let
        respText =
            case r.crt of
                RemoteData.NotAsked ->
                    "Not asked"

                RemoteData.Loading ->
                    "Loading"

                RemoteData.Failure e ->
                    case e of
                        Http.BadUrl u ->
                            "Bad URL: " ++ u

                        Http.Timeout ->
                            "Timeout"

                        Http.NetworkError ->
                            "Network error"

                        Http.BadStatus s ->
                            "Bad status: " ++ String.fromInt s

                        Http.BadBody s ->
                            "Bad body: " ++ s

                RemoteData.Success s ->
                    "Success " ++ s

        a =
            Html.article [ class "card" ]
                [ Html.header [] [ Html.h3 [] [ text "Certificate" ] ]
                , Html.h4 [] [ text "Request" ]
                , Html.p [] [ text r.key ]
                , Html.h4 [] [ text "Response" ]
                , Html.p [] [ text respText ]
                ]
    in
    a :: acc


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = \_ -> Sub.none
        , update = update
        , view = view
        }
