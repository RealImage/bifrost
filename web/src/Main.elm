module Main exposing (Msg(..), main, update, view)

import Array exposing (Array)
import Browser
import File exposing (File)
import File.Select
import Html exposing (Html, article, button, header, main_, section, text)
import Html.Attributes exposing (class)
import Html.Events exposing (onClick)
import Http
import RemoteData exposing (RemoteData)
import Task
import UUID exposing (UUID)


type alias Model =
    { namespace : RemoteData String UUID
    , requests : Array Request
    }


type alias Request =
    { crt : RemoteData String String
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
            ( model
            , Cmd.batch <| List.map (\f -> Task.perform FileRead (File.toString f)) (file :: files)
            )

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

                Result.Err e ->
                    case e of
                        UUID.UnsupportedVariant ->
                            RemoteData.Failure "Unsupported variant"

                        UUID.WrongFormat ->
                            RemoteData.Failure "Wrong format"

                        UUID.WrongLength ->
                            RemoteData.Failure "Wrong length"

                        UUID.NoVersion ->
                            RemoteData.Failure "No version"

                        UUID.IsNil ->
                            RemoteData.Failure "Is nil"

        Result.Err e ->
            case e of
                Http.BadUrl u ->
                    RemoteData.Failure <| "Bad URL: " ++ u

                Http.Timeout ->
                    RemoteData.Failure "Timeout"

                Http.NetworkError ->
                    RemoteData.Failure "Network error"

                Http.BadStatus s ->
                    RemoteData.Failure <| "Bad status: " ++ String.fromInt s

                Http.BadBody s ->
                    RemoteData.Failure <| "Bad body: " ++ s


view : Model -> Browser.Document Msg
view model =
    { title = "Bifrost - Issue Certificates"
    , body =
        [ Html.nav
            [ class "container-fluid" ]
            [ Html.ul [] [ Html.li [] [ text "Bifrost" ] ] ]
        , header [ class "container" ]
            [ hgroup
                []
                [ Html.h1 [] [ text "Certificate Issuer" ]
                , Html.p [] [ text "Hot off the presses" ]
                ]
            , section []
                [ Html.h2 [] [ text "New Request" ]
                , button [ class "button" ] [ text "Generate private key" ]
                , button [ class "button", onClick OpenFilesClicked ] [ text "Upload private keys" ]
                ]
            ]
        , main_ [ class "container" ]
            [ section []
                [ Html.h2 [] [ text "Requests" ]
                , Html.div [ class "grid" ] <| Array.foldl viewRequests [] model.requests
                ]
            ]
        ]
    }


viewRequests : Request -> List (Html a) -> List (Html a)
viewRequests r acc =
    let
        respText =
            case r.crt of
                RemoteData.NotAsked ->
                    "Not asked"

                RemoteData.Loading ->
                    "Loading"

                RemoteData.Failure s ->
                    "Failed " ++ s

                RemoteData.Success s ->
                    "Success " ++ s

        a =
            article []
                [ header [] [ Html.h3 [] [ text "Certificate" ] ]
                , Html.h4 [] [ text "Request" ]
                , Html.p [] [ text r.key ]
                , Html.h4 [] [ text "Response" ]
                , Html.p [] [ text respText ]
                ]
    in
    a :: acc


hgroup : List (Html.Attribute a) -> List (Html.Html a) -> Html.Html a
hgroup =
    Html.node "hgroup"


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = \_ -> Sub.none
        , update = update
        , view = view
        }
